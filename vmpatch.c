/*
	vmsplice kernel vulnerability protection module
	by hkpco (Chanam Park)
	chanam.park@hkpco.kr
	http://hkpco.kr/
*/

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/uio.h>
#include <asm/unistd.h>
#include <asm/uaccess.h>
#include <asm/pgtable.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION( 2, 6, 24 )
#include <asm-i386/cacheflush.h>

#else
#include <asm-x86/cacheflush.h>

#endif

#define SET	0
#define ON	1
#define OFF	2

void **sys_call_table;

asmlinkage long (*orig_vmsplice)( int fd, const struct iovec *iov, unsigned long nr_segs, unsigned int flags );
asmlinkage long hk_vmsplice( int fd, const struct iovec *iov, unsigned long nr_segs, unsigned int flags )
{
	mm_segment_t fs = get_fs();
	set_fs(KERNEL_DS);

	if(!access_ok( VERIFY_READ, iov->iov_base , iov->iov_len ))
		return -EFAULT;

	set_fs(fs);

	return orig_vmsplice( fd, iov, nr_segs, flags );
}
asmlinkage int (*orig_vm86old)( struct vm86_struct *info );
asmlinkage int hk_vm86old( struct vm86_struct *info )
{
	return -EFAULT;
}

unsigned int *get_sys_call_table( void )
{
	int cnt;
	unsigned int sys_offset;
	char pattern[] = "\xff\x14\x85";

	struct {
		unsigned short limit;
		unsigned int base;
	} __attribute__ ((packed)) idtr;
	struct idt_gate {
		unsigned short off1;
		unsigned short sel;
		unsigned char none,flags;
		unsigned short off2;
	} __attribute__ ((packed)) *idt;

	asm( "sidt %0" : "=m"(idtr) );
	idt = (struct idt_gate *)( idtr.base + 0x80*8 );
	sys_offset = ((idt->off2) << 16) | (idt->off1);

	for( cnt = 0 ; cnt < 500 ; cnt++, sys_offset++ )
	{
		if( !strncmp( (char *)sys_offset , pattern , strlen(pattern) ))
			return (unsigned int *)(*((unsigned int *)(sys_offset +strlen(pattern))));
	}

	return NULL;
}

int hk_attr_change( unsigned long linear_addr , int attr , int flag , int *value )
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	pgd = pgd_offset_k( linear_addr );
	if(!pgd_present(*pgd)) {
		if(pgd_none(*pgd))
			return -0x10;

		return -0x01;
	}

	pud = pud_offset( pgd, linear_addr );
	if(!pud_present(*pud)) {
		if(pud_none(*pud))
			return -0x20;

		return -0x02;
	}

	pmd = pmd_offset( pud, linear_addr );
	if(!pmd_present(*pmd)) {
		if(pmd_none(*pmd))
			return -0x30;

		return -0x03;
	}

	if( pmd_large(*pmd) )
		pte = (pte_t *)pmd;

	else
		pte = pte_offset_kernel( pmd, linear_addr );

	if(!pte_present(*pte)) {
		if( pte_none(*pte))
			return -0x40;

		return -0x04;
	}

	if( value > 0 )
		*value = (pte)->pte_low;

	if( flag == 0 )		(pte)->pte_low = attr;
	else if( flag == 1 ) 	(pte)->pte_low |= attr;
	else if( flag == 2 ) 	(pte)->pte_low &= ~attr;
	else;

	global_flush_tlb();

	return 0;
}

int __init hk_init( void )
{
	int rtn, val;

	sys_call_table = (void **)get_sys_call_table();
	if( sys_call_table == NULL ) {
		printk( KERN_ALERT "[!] Can not find the sys_call_table address\n" );
		return -1;
	}

	rtn = hk_attr_change( (unsigned long)sys_call_table, _PAGE_RW, ON, &val );
	if( rtn != 0 ) {
		printk( KERN_ALERT "[!] hk_attr_change() function error\n" );

		if( (-rtn) & 0x0F )
			printk( KERN_ALERT "[!] <The page is not in main memory>\n\terror code = -0x%02x\n" , -rtn );

		else if( (-rtn) & 0xF0 )
			printk( KERN_ALERT "[!] <Entry is null>\n\terror code = -0x%02x\n" , -rtn );

		return -1;
	}

	orig_vmsplice = sys_call_table[__NR_vmsplice];
	orig_vm86old = sys_call_table[__NR_vm86old];
	sys_call_table[__NR_vmsplice] = hk_vmsplice;
	sys_call_table[__NR_vm86old] = hk_vm86old;

	rtn = hk_attr_change( (unsigned long)sys_call_table, val, SET, NULL );
	if( rtn != 0 )
		printk( KERN_ALERT "[!] hk_init(): sys_call_table attribute recovery failed\n" );

	printk( KERN_ALERT "[+] vmsplice kernel vulnerability protection module loaded\n" );
	printk( KERN_ALERT "[+] patched by hkpco\n" );

	return 0;
}

void __exit hk_exit( void )
{
	int rtn, val;

	rtn = hk_attr_change( (unsigned long)sys_call_table, _PAGE_RW, ON, &val );
	if( rtn == 0 )
	{
		sys_call_table[__NR_vmsplice] = orig_vmsplice;
		sys_call_table[__NR_vm86old] = orig_vm86old;

		rtn = hk_attr_change( (unsigned long)sys_call_table, val, SET, NULL );
		if( rtn != 0 )
			printk( KERN_ALERT "[!] hk_exit(): sys_call_table attribute recovery failed\n" );
	}
	else
	{
		printk( KERN_ALERT "[!] vmsplice() and vm86old() syscall recovery failed\n" );
	}

	printk( KERN_ALERT "[-] protection module exit\n" );
}

module_init( hk_init );
module_exit( hk_exit );

MODULE_LICENSE( "GPL" );
MODULE_AUTHOR( "hkpco <ChanAm Park>" );