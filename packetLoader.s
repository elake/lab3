#-------------------------------
# Packet Forwarding Student Test Environment
# Author: Taylor Lloyd
# Date: June 4, 2012
#
# This code loads in a packet from a file named 
# packet.in and calls handlePacket with the 
# appropriate argument.
#
# Nothing is done with the returned values, it is up
# to the student to check them.
#
#-------------------------------

.data

packetFile:
.asciiz "./packet.dat"
.align 2
packetData:
.space 200

.text
main:
#Open the packet file
	la	$a0 packetFile #filename
	li	$a1 0x00 #flags
	li	$a2 0x0644 #file mode
	li	$v0 13 
	syscall #file_open
#Read into buffer
	move 	$a0 $v0
	la	$a1 packetData
	li	$a2 200
	li	$v0 14
	syscall #file_read
#Close the reading file
	li	$v0 16
	syscall

#Run the appended solution
	la	$a0 packetData
	jal	handlePacket
################### Here the solution can be checked for accuracy #######
	add $a0 $v0 $0
	li $v0 1
	syscall
	add $a0 $v1 $0
	li $v0 1
	syscall

	li	$v0 10
	syscall
################### Student handlePacket code begins here ###############
handlePacket:	
	lw $t0 0($a0)		# $t0 <- the first word of the packet
checkVersion:	
	sll $t1 $t0 24		# Isolate IP version
	srl $t1 $t1 28		# Isolate IP version
	li $t2 4		# IPV4
	beq $t1 $t2 checkHeader	# If version is IPV4, check header
	li $v1 2		# invalid IPv4 packet format
	li $v0 0		# drop packet
	jr $ra
checkHeader:
	lw $t0 8($a0)		# Start with checksum word
	li $t7 0xffff0000	# Can't andi directly with 16 bits
	and $t6 $t0 $t7 	# Store original checksum
	sll $t0 $t0 16		# Zero checksum
	srl $t0 $t0 16		# Realign original word
	sw $t0 8($a0)		# Replace word in packet with zero'd checksum	
	lw $t0 0($a0)		# Load first word
	sll $t0 $t0 28		# Isolate header length
	srl $t0 $t0 28		# Isolate header length
	li $t1 0		# Accumulator = 0
	add $t2 $a0 $0		# $t2 <- $a0
loop1:
	beq $t0 $0 exitloop1	# Exit if end of header reached
	lw $t3 0($t2)		# Load current word
	andi $t4 $t3 0x000000ff # Isolate first byte of half-word
	sll $t4 $t4 8		# Move byte into little endianness
	andi $t5 $t3 0x0000ff00 # Isolate second byte of half-word
	srl $t5 $t5 8		# Move byte into little endianness
	and $t4 $t5 $t4		# Combine halfword into little endian halfword
	add $t1 $t1 $t4		# Add to accumulator
	li $t7 0x00ff0000	# Can't andi directly with >16 bits
	and $t4 $t3 $t7 	# Isolate first byte of next half-word
	srl $t4 $t4 8		# Move byte into little endianness
	li $t7 0xff000000	# Can't andi directly with >16 bits
	and $t5 $t3 $t7 	# Isolate second byte of half-word
	srl $t5 $t5 24		# Move byte into little endianness
	and $t4 $t5 $t4		# Combine halfword into little endian halfword
	add $t1 $t1 $t4		# Add to accumulator
	addi $t0 $t0 -1		# Decerement words remaining in header
	addi $t2 $t2 4		# Move onto next word of header
	beq $0 $0 loop1		# Continue loop
exitloop1:
	srl $t0 $t1 16		# Isolate the carry
	add $t1 $t1 $t0		# Add the carry to the accumulator
	li $t7 0xffffffff	# Can't xor directly with >16 bits
	xor $t1 $t1 $t7 	# Take the complement of the accumulator
	li $t0 0		# $t0 will hold the big endian checksum
	andi $t2 $t1 0x000000ff # Isolate the first byte of half-word
	sll $t2 $t2 24		# Move byte into big endianness
	and $t0 $t0 $t2		# Add first byte of checksum into packet
	andi $t2 $t1 0x0000ff00 # Isolate second byte of half-word
	sll $t2 $t2 8		# Move byte into big endianness
	and $t0 $t0 $t2		# Add second byte of checksum into packet
	beq $t0 $t6 checkTTL
	li $v1 0		# Checksum fail
	li $v0 0		# drop packet
	jr $ra
checkTTL:
	lw $t0 8($a0)		# Load word at bit offset 64
	andi $t1 $t0 0x000000ff	# Isolate TTL
	slti $t1 $t1 2		# $t1 <- 1 if ttl expired
	beq $t1 $0 preparePacket # Prepare packet for forwarding
	li $v1 1		# TTL Zeroed
	li $v0 0		# drop packet
	jr $ra
preparePacket:
	lw $t0 8($a0)		# Start with TTL word
	andi $t1 $t0 0x000000ff	# Isolate TTL
	addi $t1 $t1 -1		# Decrement TTL
	srl $t0 $t0 8		# Eliminate TTL in original
	sll $t0 $t0 24		# Zero checksum for new checksum
	srl $t0 $t0 16		# Realign original word
	and $t0 $t0 $t1		# Place new TTL in word
	sw $t0 8($a0)		# Replace word in packet with new TTL and zero'd checksum
calculateChecksum:	
	lw $t0 0($a0)		# Load first word
	sll $t0 $t0 28		# Isolate header length
	srl $t0 $t0 28		# Isolate header length
	li $t1 0		# Accumulator = 0
	add $t2 $a0 $0		# $t2 <- $a0
loop:
	beq $t0 $0 exitloop	# Exit if end of header reached
	lw $t3 0($t2)		# Load current word
	andi $t4 $t3 0x000000ff # Isolate first byte of half-word
	sll $t4 $t4 8		# Move byte into little endianness
	andi $t5 $t3 0x0000ff00 # Isolate second byte of half-word
	srl $t5 $t5 8		# Move byte into little endianness
	and $t4 $t5 $t4		# Combine halfword into little endian halfword
	add $t1 $t1 $t4		# Add to accumulator
	li $t7 0x00ff0000	# Can't andi directly with >16 bits
	and $t4 $t3 $t7		# Isolate first byte of next half-word
	srl $t4 $t4 8		# Move byte into little endianness
	li $t7 0xff000000	# Can't andi directly with >16 bits
	and $t5 $t3 $t7 	# Isolate second byte of half-word
	srl $t5 $t5 24		# Move byte into little endianness
	and $t4 $t5 $t4		# Combine halfword into little endian halfword
	add $t1 $t1 $t4		# Add to accumulator
	addi $t0 $t0 -1		# Decerement words remaining in header
	addi $t2 $t2 4		# Move onto next word of header
	beq $0 $0 loop		# Continue loop
exitloop:
	srl $t0 $t1 16		# Isolate the carry
	add $t1 $t1 $t0		# Add the carry to the accumulator
	li $t7 0xffffffff	# Can't xor directly with >16 bits
	xor $t1 $t1 $t7 	# Take the complement of the accumulator
	lw $t0 8($a0)		# Load the TTL decremented word to give checksum
	andi $t2 $t1 0x000000ff # Isolate the first byte of half-word
	sll $t2 $t2 24		# Move byte into big endianness
	and $t0 $t0 $t2		# Add first byte of checksum into packet
	andi $t2 $t1 0x0000ff00 # Isolate second byte of half-word
	sll $t2 $t2 8		# Move byte into big endianness
	and $t0 $t0 $t2		# Add second byte of checksum into packet
	sw $t0 8($a0)		# Update the packet, ready to forward
	li $v0 1		# $v0 <- 1
	add $v1 $a0 $0		# $v1 <- $a0
exit:
	jr $ra
