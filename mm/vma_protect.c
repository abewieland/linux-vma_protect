#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/signal.h>
#include <linux/mm.h>
#include <linux/mmu_notifier.h>
#include <linux/syscalls.h>
#include <linux/userfaultfd_k.h>

#include <asm/tlb.h>

/* Syscall command types */
enum vma_protect_cmd {
	VMA_ADD_ADDR = 0,
	VMA_OPEN,
	VMA_CLOSE
};

/*
 * In most cases the number of code addresses per code mapping -- protected
 * mapping pair should be quite small, so a list is used. If this becomes a
 * bottleneck, an RB tree could be substituted.
 */
struct bare_addr {
	unsigned long addr;
	struct list_head link;
};

/*
 * The number of code mappings per protected mapping (and vice versa) should
 * both be _very_ small (usually only one), so again a list is used. Trees
 * could be used if needed.
 */
struct vma_prot_addr {
	struct vm_area_struct *code;
	struct list_head prot_link;
	struct list_head code_link;
	struct list_head addrs;
};

static void free_vpa(struct vma_prot_addr *vpa) {
	struct bare_addr *ba, *tmp;
	list_for_each_entry_safe(ba, tmp, &vpa->addrs, link) {
		list_del(&ba->link);
		kfree(ba);
	}
	kfree(vpa);
}

void vma_protect_cleanup(struct vm_area_struct *vma)
{
	struct vma_prot_addr *vpa, *tmp;
	if (vma->vm_flags & VM_PROTECT) {
		atomic_dec(&vma->vm_mm->protect_vm);
		list_for_each_entry_safe(vpa, tmp, &vma->vm_prot_addrs, prot_link) {
			list_del(&vpa->prot_link);
			list_del(&vpa->code_link);
			if (list_empty(&vpa->code->vm_prot_addrs) &&
			    vpa->code->vm_prot_state)
				vpa->code->vm_flags |= VM_MAYWRITE;
			free_vpa(vpa);
		}
	} else {
		list_for_each_entry_safe(vpa, tmp, &vma->vm_prot_addrs, code_link) {
			list_del(&vpa->prot_link);
			list_del(&vpa->code_link);
			free_vpa(vpa);
		}

	}
}

#define PROT_MASK	(VM_READ | VM_WRITE | VM_EXEC | VM_SHARED | \
			 VM_MAYREAD | VM_MAYWRITE | VM_MAYEXEC | VM_MAYSHARE)
#define CLOSED		(PROT_MASK+1)

static struct vma_prot_addr *find_vpa_prot(struct vm_area_struct *prot,
					   struct vm_area_struct *code)
{
	struct vma_prot_addr *vpa;
	list_for_each_entry(vpa, &prot->vm_prot_addrs, prot_link) {
		if (vpa->code == code)
			return vpa;
	}
	return NULL;
}

static bool find_addr(struct mm_struct *mm, struct vm_area_struct *prot,
		      unsigned long addr)
{
	struct vm_area_struct *code;
	struct vma_prot_addr *vpa;
	struct bare_addr *ba;

	code = find_vma(mm, addr);
	vpa = find_vpa_prot(prot, code);

	if (vpa) {
		list_for_each_entry(ba, &vpa->addrs, link) {
			if (ba->addr == addr)
				return true;
		}
	}

	return false;
}

static int add_addr(struct vm_area_struct *prot, struct vm_area_struct *code,
		    unsigned long addr)
{
	struct vma_prot_addr *vpa = NULL;
	struct bare_addr *ba = NULL;

	vpa = find_vpa_prot(prot, code);
	if (!vpa) {
		vpa = kmalloc(sizeof *vpa, GFP_KERNEL);
		if (!vpa)
			return -ENOMEM;
		vpa->code = code;
		if (list_empty(&code->vm_prot_addrs)) {
			code->vm_prot_state = !!(code->vm_flags & VM_MAYWRITE);
			code->vm_flags &= ~VM_MAYWRITE;
		}
		list_add(&vpa->code_link, &code->vm_prot_addrs);
		list_add(&vpa->prot_link, &prot->vm_prot_addrs);
		INIT_LIST_HEAD(&vpa->addrs);
	}

	list_for_each_entry(ba, &vpa->addrs, link) {
		if (ba->addr == addr)
			return 0;
	}
	ba = kmalloc(sizeof *ba, GFP_KERNEL);
	if (!ba)
		return -ENOMEM;
	ba->addr = addr;
	list_add(&ba->link, &vpa->addrs);

	return 0;
}

static int change_mappings(struct mm_struct *mm, struct vm_area_struct *vma,
			   unsigned long newflags)
{
	struct mmu_gather tlb;
	struct vm_area_struct *prev;
	int ret;
	MA_STATE(mas, &mm->mm_mt, vma->vm_start, vma->vm_end - 1);

	prev = mas_prev(&mas, 0);
	tlb_gather_mmu(&tlb, mm);
	ret = mprotect_fixup(&tlb, vma, &prev, vma->vm_start, vma->vm_end,
			     newflags);
	tlb_finish_mmu(&tlb);
	return ret;
}

SYSCALL_DEFINE3(vma_protect, unsigned long, addr, unsigned long, cmd,
	       unsigned long, arg)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma, *code_vma;
	unsigned long flags;
	sigset_t mask;
	int ret = -EINVAL;

	addr = untagged_addr(addr);

	if (mmap_write_lock_killable(mm))
		return -EINTR;

	vma = vma_lookup(mm, addr);
	if (!vma || !(vma->vm_flags & VM_PROTECT))
		goto out;

	switch (cmd) {
	case VMA_ADD_ADDR:
		if (vma->vm_prot_state)
			break;
		arg = untagged_addr(arg);
		code_vma = find_vma(mm, arg);
		if (!code_vma || code_vma->vm_start > arg ||
		    code_vma->vm_flags & (VM_WRITE|VM_PROTECT))
			break;
		ret = add_addr(vma, code_vma, arg);
		break;
	case VMA_OPEN:
		if (!vma->vm_prot_state)
			break;
		if (!find_addr(mm, vma, KSTK_EIP(current))) {
			ret = -EFAULT;
			break;
		}
		/* matched with restore_saved_sigmask in close below */
		set_restore_sigmask();
		current->saved_sigmask = current->blocked;
		sigfillset(&mask);
		set_current_blocked(&mask);
		flags = (vma->vm_flags & ~PROT_MASK) |
			(vma->vm_prot_state & PROT_MASK);
		ret = change_mappings(mm, vma, flags);
		if (ret)
			break;
		vma->vm_prot_state = 0;
		break;
	case VMA_CLOSE:
		if (vma->vm_prot_state)
			break;
		restore_saved_sigmask();
		flags = CLOSED | (vma->vm_flags & PROT_MASK);
		ret = change_mappings(mm, vma, vma->vm_flags & ~PROT_MASK);
		if (ret)
			break;
		vma->vm_prot_state = flags;
		break;
	default:
		break;
	}

out:
	mmap_write_unlock(mm);
	return ret;
}
