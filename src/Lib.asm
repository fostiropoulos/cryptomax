;; Author:  Iordanis Fostiropoulos, ifostiropoul2011@my.fit.edu
;; Course:  CSE 3120
;; Project: CryptoMax



INCLUDE Irvine32.inc

; Structure used for the mouse pointer
POINT STRUCT
   ; x coordinate is the horizontal line with 0 being
   ; the left of the screen and the maximum value being
   ; the right of the screen
	x 	DWORD ? 
   ; y coordinate is the vertical line with 0 being
   ; the top of the screen and the maximum value being
   ; the bottom of the screen
	y 	DWORD ?
POINT ENDS

; Structure that stores the key and its length
CREDENTIALS STRUCT 
   ; key is a pointer to a string
	key DWORD ?
   ; key length is the length of the key initially zero
	keyLength DWORD 0
CREDENTIALS ENDS


;---------------INTERNAL PROCEDURES-----------------------
; Opens a file containing encryption key
openEncryptionKey PROTO C, fileName:PTR BYTE
; Saves a key to a file
saveKey PROTO C, fileName:PTR BYTE, keyPTR:PTR CREDENTIALS
; Offsets all the bytes of the file by a rotating keyword
offsetFileBytes PROTO C, fileName:PTR BYTE, keyword:PTR BYTE,
                        keywordLength:DWORD, isNegativeOffset:BYTE
; generate a key using the mouse
generateMouseKey PROTO C
; generate a random key
generateRandomKey PROTO C
; finds the mod of number%256
modular PROTO
;---------------------------------------------------------
          
;---------------EXTERNAL PROCEDURES-----------------------
; External C procedure, deletes a file
remove PROTO C, filename:PTR BYTE
; Win32 procedure to get the coordinates of the cursor
GetCursorPos PROTO, p:PTR POINT
; Win32 procedure to get the size of the file to determine how
; many bytes it contains
GetFileSize PROTO, hFile:DWORD,lpFileSizeHigh:PTR DWORD
; Sleep procedure not currently used in the code.
; it can be added to add a bigger randomization factor
; to the mouse generated key. 
Sleep PROTO, p:DWORD
;---------------------------------------------------------


.data

; create data segment for key
; size is 256 to have a null terminated
; key. This way it is less error prone for 
; buffer overflow. 
key BYTE 256 DUP(0)

; Variables used by 
; generateMouseKey PROC
prevX DWORD 0
prevY DWORD 0
curX DWORD 0
curY DWORD 0

; Pointer that points at the address of the stack
; that the file buffer is stored.
fileDataStackPtr DWORD 0

; File handlers variables
inputFileHandler DWORD ?
outputFileHandler DWORD ?

; The size of the input file
inputFileSize DWORD ?

; Data structure that is used to return the mouse coordinates
mouseData POINT <>

; Credentials structure that stores the size and address of the key location
credential CREDENTIALS <OFFSET key>


.code

;---------------------------------------------
moveFileToBuffer MACRO fileName
; Opens a file and transfers its contents to
; the stack.
; Input: fileName, the location of the file to be
; opened
; WARNING: If the input file is too big, it will
; cause stack overflow. Workaround is discussed
; in the report.
;---------------------------------------------


   ; open file segment and save to buffer
	mov	edx, fileName
	call	OpenInputFile
	;cmp eax,-1
	;je returnFalse
	mov inputFileHandler,eax
	INVOKE GetFileSize, 
				eax,NULL
	mov inputFileSize, eax

	sub esp,inputFileSize
	mov fileDataStackPtr,esp
	mov eax, inputFileHandler
	mov edx, esp
	mov ecx,inputFileSize
	call ReadFromFile
	mov eax,inputFileHandler
	call CloseFile 
   ; end of open file segment
   	


   
ENDM

;---------------------------------------------
moveBufferToFile MACRO fileName
; Opens a file and transfers the contents of
; the stack.
; Input: fileName, the location of the file to be
; opened
;---------------------------------------------

  ; delete existing file and replace it with the buffer we have
	INVOKE remove,
				fileName
	mov edx, fileName
	call CreateOutputFile
	mov outputFileHandler,eax
   ; write data to file
	mov eax,outputFileHandler
	mov edx, fileDataStackPtr
	mov ecx,inputFileSize
	call WriteToFile
   add esp, inputFileSize
   ; close file
	mov eax,outputFileHandler
	call CloseFile 
   
ENDM

;---------------------------------------------
modular PROC
; Takes a value and finds its mod of 256
; if the value is negative it adds 256 to the final
; value to normalize it.
; Input: EAX, number whose mod to find
; Output: EAX, final value
;---------------------------------------------

	mov eax,[esp+4]
	
	; eax= eax%256
	; this code sample was copied and modified from
   ;   http://stackoverflow.com/questions/8231882/how-to-implement-the-mod-operator-in-assembly
	MOV ECX,255
	CDQ ;this will clear EDX due to the sign extension
	IDIV ECX
	MOV EAX,EDX

	; because modular for negative numbers
	; is defined differently, if the final number is negative
	; we add the offset of 256
	cmp eax,0
	jge procedureEnd
	add EAX,256
	procedureEnd:
	mov [esp+4],eax
	ret	

modular ENDP

;---------------------------------------------
saveKey PROC C,fileName:PTR BYTE,
               keyPTR:PTR CREDENTIALS
; Save key to file
; Input: FileName, string to file
;        keyPTR, the pointer to the key structure
; Output: no output
;---------------------------------------------

	INVOKE remove,
				fileName
	mov edx, fileName
	call CreateOutputFile
	mov outputFileHandler,eax
	mov eax,[keyPTR]
	mov edx, [eax].CREDENTIALS.key
	mov ecx,[eax].CREDENTIALS.keyLength
	mov eax,outputFileHandler
	call WriteToFile
	mov eax,inputFileHandler
	call CloseFile 

	ret
saveKey ENDP

;---------------------------------------------
openEncryptionKey PROC C,fileName:PTR BYTE
; Opens encryption key and returns the key in
; a datastructure of type Credentials
; Input: fileName, Path to the file containing the key
; Output: PTR CREDENTIALS, contains the key
;---------------------------------------------
	
	moveFileToBuffer fileName
   
   ; error checking
   cmp inputFileSize,0
	je finish
   
	mov ecx,0
   ; copy string procedure from buffer to memory
	copyStr:
      
      mov edx, fileDataStackPtr
      mov eax,0
      mov al,BYTE PTR [edx+ecx]
      mov key[ecx],al
      inc ecx
      
	cmp ecx,inputFileSize
	jne copyStr
	
	add esp,inputFileSize
	finish:
	
   ; output the structure
	mov eax, inputFileSize
	mov credential.keyLength, eax
	mov eax, OFFSET credential
	ret
openEncryptionKey ENDP


;---------------------------------------------
offsetFileBytes PROC C,
            fileName:PTR BYTE,
            keyword:PTR BYTE,
            keywordLength:DWORD,
            isNegativeOffset:BYTE
; Main encryption function.
; offsets all the bytes upward or downward (addition or substraction)
; to obscure their information. 
; Input: fileName, the location of the file to open
;        keyword, the keyword string
;        keywordLength the size of the keyword
;        isNegativeOffset, true for decryption, false for encryption
;          it is the offset by which we move the bytes
;---------------------------------------------
                  
   moveFileToBuffer fileName



   ; loop through data in the memory and 
   ; rotate them
	mov ecx,0 ; Primary Pointer
	mov ebx,0 ; Secondary Pointer
	readDataTop:

	push ecx
	push ebx

	mov eax,0
	mov edx, fileDataStackPtr
	mov al, [edx+ecx]
	mov edx, keyword
   
   ; negative offset means substraction
   cmp isNegativeOffset,0
   je fileEncoding
      sub al, [edx+ebx] ; decoding
   jmp endOfEncoding
   fileEncoding:
      add al, [edx+ebx] ; encoding
   endOfEncoding:
   
	push eax
	call modular
	pop eax
   
   ; restore pointers
	pop ebx
	pop ecx
   
   ; write the data to the memory
	mov edx, fileDataStackPtr
	mov [edx+ecx],al
	inc ecx
	inc ebx
	cmp ebx, keywordLength
	jne keyElementWithinLimits
	mov ebx,0
	keyElementWithinLimits:
	cmp ecx,inputFileSize
	jne readDataTop


   moveBufferToFile fileName


	; return true
	mov eax,1
	jmp procedureEnd
	returnFalse:
	; return false
	mov eax,0
	procedureEnd:
	
 	ret
offsetFileBytes ENDP

;---------------------------------------------
generateRandomKey PROC C
; Generates a random key
; Input: no input
; Output: A credentials structure with the key.
;---------------------------------------------

	INVOKE Randomize
	mov ecx,0
	top:
	mov eax, 256
	push ecx
	INVOKE RandomRange
	push eax
	call modular
	pop eax
	pop ecx
	mov key[ecx],al
	inc ecx
	cmp ecx,255
	jne top
	mov credential.keyLength,255
	mov eax, OFFSET credential
	ret
generateRandomKey ENDP

;---------------------------------------------
generateMouseKey PROC C
;
; Inputs an integer n and displays a
; multiplication table ranging from n * 2^1
; to n * 2^10.
;----------------------------------------------
	mov ecx, 0
	top:
		; calculated time it takes to generate a
		; 255 byte key over 20 seconds  (20/(255/2))
		; 20 seconds divided by 255(key size) divided by 2 (the coordinates)
		push ecx
			; induce randomize factor
			;INVOKE Sleep, 156
			INVOKE GetCursorPos, 
					ADDR mouseData
            ; find the mod number of the coordinates
				push mouseData.x
				call modular
				pop eax
		pop ecx
      ; compare the data of the cordinates with before
      ; to avoid repetitive keyword terms 
		cmp eax,prevX
		je top
			mov curX, eax
			mov prevX,eax
		push ecx
            ; find the mod number of the coordinates
				push mouseData.y
				call modular
				pop eax
		pop ecx
			cmp eax,prevY
			je top
			mov curY,eax
			mov prevY,eax
      
      ; if the coordinates' mod 256 is unique
      ; move them to the key memory
		mov eax, curX
		mov key[ecx],al
		inc ecx

		mov eax, curY
		mov key[ecx],al
		inc ecx
   ; generate 255 byte key
	cmp ecx,255
	jb top
   ; return
	mov credential.keyLength,255
	mov eax, OFFSET credential
	ret
generateMouseKey ENDP

END