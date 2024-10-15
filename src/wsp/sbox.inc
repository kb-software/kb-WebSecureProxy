;--------------------------------------------------------------
; AES S-Box used for Encryption
; Used for assembler, taken from sbox.h (program generated)
;--------------------------------------------------------------
SBox label BYTE
	DB 063h, 07Ch, 077h, 07Bh, 0F2h, 06Bh, 06Fh, 0C5h 	; 00-07
	DB 030h, 001h, 067h, 02Bh, 0FEh, 0D7h, 0ABh, 076h 	; 08-0F
	DB 0CAh, 082h, 0C9h, 07Dh, 0FAh, 059h, 047h, 0F0h 	; 10-17
	DB 0ADh, 0D4h, 0A2h, 0AFh, 09Ch, 0A4h, 072h, 0C0h 	; 18-1F

	DB 0B7h, 0FDh, 093h, 026h, 036h, 03Fh, 0F7h, 0CCh 	; 20-27
	DB 034h, 0A5h, 0E5h, 0F1h, 071h, 0D8h, 031h, 015h 	; 28-2F
	DB 004h, 0C7h, 023h, 0C3h, 018h, 096h, 005h, 09Ah 	; 30-37
	DB 007h, 012h, 080h, 0E2h, 0EBh, 027h, 0B2h, 075h 	; 38-3F

	DB 009h, 083h, 02Ch, 01Ah, 01Bh, 06Eh, 05Ah, 0A0h 	; 40-47
	DB 052h, 03Bh, 0D6h, 0B3h, 029h, 0E3h, 02Fh, 084h 	; 48-4F
	DB 053h, 0D1h, 000h, 0EDh, 020h, 0FCh, 0B1h, 05Bh 	; 50-57
	DB 06Ah, 0CBh, 0BEh, 039h, 04Ah, 04Ch, 058h, 0CFh 	; 58-5F

	DB 0D0h, 0EFh, 0AAh, 0FBh, 043h, 04Dh, 033h, 085h 	; 60-67
	DB 045h, 0F9h, 002h, 07Fh, 050h, 03Ch, 09Fh, 0A8h 	; 68-6F
	DB 051h, 0A3h, 040h, 08Fh, 092h, 09Dh, 038h, 0F5h 	; 70-77
	DB 0BCh, 0B6h, 0DAh, 021h, 010h, 0FFh, 0F3h, 0D2h 	; 78-7F

	DB 0CDh, 00Ch, 013h, 0ECh, 05Fh, 097h, 044h, 017h 	; 80-87
	DB 0C4h, 0A7h, 07Eh, 03Dh, 064h, 05Dh, 019h, 073h 	; 88-8F
	DB 060h, 081h, 04Fh, 0DCh, 022h, 02Ah, 090h, 088h 	; 90-97
	DB 046h, 0EEh, 0B8h, 014h, 0DEh, 05Eh, 00Bh, 0DBh 	; 98-9F

	DB 0E0h, 032h, 03Ah, 00Ah, 049h, 006h, 024h, 05Ch 	; A0-A7
	DB 0C2h, 0D3h, 0ACh, 062h, 091h, 095h, 0E4h, 079h 	; A8-AF
	DB 0E7h, 0C8h, 037h, 06Dh, 08Dh, 0D5h, 04Eh, 0A9h 	; B0-B7
	DB 06Ch, 056h, 0F4h, 0EAh, 065h, 07Ah, 0AEh, 008h 	; B8-BF

	DB 0BAh, 078h, 025h, 02Eh, 01Ch, 0A6h, 0B4h, 0C6h 	; C0-C7
	DB 0E8h, 0DDh, 074h, 01Fh, 04Bh, 0BDh, 08Bh, 08Ah 	; C8-CF
	DB 070h, 03Eh, 0B5h, 066h, 048h, 003h, 0F6h, 00Eh 	; D0-D7
	DB 061h, 035h, 057h, 0B9h, 086h, 0C1h, 01Dh, 09Eh 	; D8-DF

	DB 0E1h, 0F8h, 098h, 011h, 069h, 0D9h, 08Eh, 094h 	; E0-E7
	DB 09Bh, 01Eh, 087h, 0E9h, 0CEh, 055h, 028h, 0DFh 	; E8-EF
	DB 08Ch, 0A1h, 089h, 00Dh, 0BFh, 0E6h, 042h, 068h 	; F0-F7
	DB 041h, 099h, 02Dh, 00Fh, 0B0h, 054h, 0BBh, 016h 	; F8-FF

;--------------------------------------------------------------
; AES S-Box used for Decryption
;--------------------------------------------------------------
InvSBox	label	BYTE
	DB 052h, 009h, 06Ah, 0D5h, 030h, 036h, 0A5h, 038h 	; 00-07
	DB 0BFh, 040h, 0A3h, 09Eh, 081h, 0F3h, 0D7h, 0FBh 	; 08-0F
	DB 07Ch, 0E3h, 039h, 082h, 09Bh, 02Fh, 0FFh, 087h 	; 10-17
	DB 034h, 08Eh, 043h, 044h, 0C4h, 0DEh, 0E9h, 0CBh 	; 18-1F

	DB 054h, 07Bh, 094h, 032h, 0A6h, 0C2h, 023h, 03Dh 	; 20-27
	DB 0EEh, 04Ch, 095h, 00Bh, 042h, 0FAh, 0C3h, 04Eh 	; 28-2F
	DB 008h, 02Eh, 0A1h, 066h, 028h, 0D9h, 024h, 0B2h 	; 30-37
	DB 076h, 05Bh, 0A2h, 049h, 06Dh, 08Bh, 0D1h, 025h 	; 38-3F

	DB 072h, 0F8h, 0F6h, 064h, 086h, 068h, 098h, 016h 	; 40-47
	DB 0D4h, 0A4h, 05Ch, 0CCh, 05Dh, 065h, 0B6h, 092h 	; 48-4F
	DB 06Ch, 070h, 048h, 050h, 0FDh, 0EDh, 0B9h, 0DAh 	; 50-57
	DB 05Eh, 015h, 046h, 057h, 0A7h, 08Dh, 09Dh, 084h 	; 58-5F

	DB 090h, 0D8h, 0ABh, 000h, 08Ch, 0BCh, 0D3h, 00Ah 	; 60-67
	DB 0F7h, 0E4h, 058h, 005h, 0B8h, 0B3h, 045h, 006h 	; 68-6F
	DB 0D0h, 02Ch, 01Eh, 08Fh, 0CAh, 03Fh, 00Fh, 002h 	; 70-77
	DB 0C1h, 0AFh, 0BDh, 003h, 001h, 013h, 08Ah, 06Bh 	; 78-7F

	DB 03Ah, 091h, 011h, 041h, 04Fh, 067h, 0DCh, 0EAh 	; 80-87
	DB 097h, 0F2h, 0CFh, 0CEh, 0F0h, 0B4h, 0E6h, 073h 	; 88-8F
	DB 096h, 0ACh, 074h, 022h, 0E7h, 0ADh, 035h, 085h 	; 90-97
	DB 0E2h, 0F9h, 037h, 0E8h, 01Ch, 075h, 0DFh, 06Eh 	; 98-9F

	DB 047h, 0F1h, 01Ah, 071h, 01Dh, 029h, 0C5h, 089h 	; A0-A7
	DB 06Fh, 0B7h, 062h, 00Eh, 0AAh, 018h, 0BEh, 01Bh 	; A8-AF
	DB 0FCh, 056h, 03Eh, 04Bh, 0C6h, 0D2h, 079h, 020h 	; B0-B7
	DB 09Ah, 0DBh, 0C0h, 0FEh, 078h, 0CDh, 05Ah, 0F4h 	; B8-BF

	DB 01Fh, 0DDh, 0A8h, 033h, 088h, 007h, 0C7h, 031h 	; C0-C7
	DB 0B1h, 012h, 010h, 059h, 027h, 080h, 0ECh, 05Fh 	; C8-CF
	DB 060h, 051h, 07Fh, 0A9h, 019h, 0B5h, 04Ah, 00Dh 	; D0-D7
	DB 02Dh, 0E5h, 07Ah, 09Fh, 093h, 0C9h, 09Ch, 0EFh 	; D8-DF

	DB 0A0h, 0E0h, 03Bh, 04Dh, 0AEh, 02Ah, 0F5h, 0B0h 	; E0-E7
	DB 0C8h, 0EBh, 0BBh, 03Ch, 083h, 053h, 099h, 061h 	; E8-EF
	DB 017h, 02Bh, 004h, 07Eh, 0BAh, 077h, 0D6h, 026h 	; F0-F7
	DB 0E1h, 069h, 014h, 063h, 055h, 021h, 00Ch, 07Dh 	; F8-FF
