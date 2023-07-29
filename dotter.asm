; by hkpco(Chanam Park)
; chanam.park@hkpco.kr
; http://hkpco.kr/
; 2009

hk segment

	org 100h
	jmp start

	scan_code	db	?	; for the value from keyboard
	row		dw	100
	col		dw	130
	_row		dw	?
	_col		dw	?


start:
_interrupt_setting:
	mov ax, 0
	mov es, ax
	mov word ptr es:[36], int_kbd_rt	; modifying IDT
	mov word ptr es:[38], cs

	call set_video_mode

_lp:	; infinite loop
	call chk_kbd		; check scancode
	call dotter		; dot printer
	call delay
	jmp _lp			; loop until press 'q'

_exit:
	mov ah, 4ch
	int 21h


set_video_mode:
	mov ah, 0
	mov al, 13h
	int 10h
	ret


int_kbd_rt:
	in al, 60h
	mov scan_code, al	; get the scan_code
	mov al, 20h
	out 20h, al
	iret


chk_kbd:
	mov ax, row
	mov _row, ax
	mov ax, col
	mov _col, ax

__ck_right:
	cmp scan_code, 0A0h 	; scancode 'd'
	jnz __ck_left
	inc col		; increase a ROW value
	jmp __ck_ret

__ck_left:
	cmp scan_code, 9Eh 	; scancode 'a'
	jnz __ck_up
	dec col		; decrease a ROW value
	jmp __ck_ret

__ck_up:
	cmp scan_code, 9Fh 	; scancode 'w'
	jnz __ck_down
	inc row		; increase a COL value
	jmp __ck_ret

__ck_down:
	cmp scan_code, 91h 	; scancode 's'
	jnz __ck_quit
	dec row		; decrease a COL value
	jmp __ck_ret

__ck_quit:
	cmp scan_code, 90h 	; scancode 'q'
	jnz __ck_ret
	jmp _exit	; exit the entire program

__ck_ret:
	ret


_remove_dot:
	mov ah, 0ch
	mov cx, _col
	mov dx, _row
	mov al, 0
	int 10h
	ret

dotter:
	call _remove_dot
	mov ah, 0ch	; write a pixel
	mov cx, col	; column
	mov dx, row	; row
	mov al, 15	; color(white)
	int 10h
	ret


delay:
	mov ax, 5000d
__dl_1:
	mov cx, 10000d
	dec ax
	jz __dl_exit

__dl_2:
	dec cx
	jnz __dl_2
	jmp __dl_1

__dl_exit:
	ret


hk ends
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  