#---------------------------------------------------------------
# Assignment:           3
# Due Date:             March 3, 2014
# Name:                 Eldon Lake
# Unix ID:              elake
# Lecture Section:      B1
# Instructor:           Jacqueline Smith
# Lab Section:          H02 (Wednesday 1400 - 1700)
# Teaching Assistant:   Mike Mills
#---------------------------------------------------------------

.text
#---------------------------------------------------------------
# The handlePacket subroutine inspects a packet and if it is a
# valid candidate for forwarding, prepares it for forwarding,
# otherwise it drops it and specifies the reason for doing so.
#
# Arguments:
# 	$a0: The address of the packet to be inspected
# Registers:
#
#---------------------------------------------------------------

handlePacket:	
	lw $t0 0($a0)		# $t0 <- the first word of the packet
checkVersion:	
	srl $t1 $t0 28		# Isolate IP version
	li $t2 0x00000004	# IPV4
	beq $t1 $t2 checkHeader	# If version is IPV4, check header
	li $v1 2		# invalid IPv4 packet format
	li $v0 0		# drop packet
	jr $ra
checkHeader:
	lw $t0 8($a0)		# Start with checksum word
	li $t7 0x0000ffff	# Can't andi directly with 16 bits
	and $t6 $t0 $t7 	# Store original checksum
	srl $t0 $t0 16		# Zero checksum
	sll $t0 $t0 16		# Realign original word
	sw $t0 8($a0)		# Replace word in packet with zero'd checksum	
	lw $t0 0($a0)		# Load first word
	sll $t0 $t0 4		# Isolate header length
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
	sll $t2 $t2 8		# Move byte into big endianness
	and $t0 $t0 $t2		# Add first byte of checksum into packet
	andi $t2 $t1 0x0000ff00 # Isolate second byte of half-word
	srl $t2 $t2 8		# Move byte into big endianness
	and $t0 $t0 $t2		# Add second byte of checksum into packet
	beq $t0 $t6 checkTTL
	li $v1 0		# Checksum fail
	li $v0 0		# drop packet
	jr $ra
checkTTL:
	lw $t0 8($a0)		# Load word at bit offset 64
	srl $t1 $t0 24		# Isolate TTL
	slti $t1 $t1 2		# $t1 <- 1 if ttl expired
	beq $t1 $0 preparePacket # Prepare packet for forwarding
	li $v1 1		# TTL Zeroed
	li $v0 0		# drop packet
	jr $ra
preparePacket:
	lw $t0 8($a0)		# Start with TTL word
	srl $t1 $t0 24		# Isolate TTL
	addi $t1 $t1 -1		# Decrement TTL
	sll $t1 $t1 24		# Realign new TTL
	sll $t0 $t0 8		# Eliminate TTL in original
	srl $t0 $t0 24		# Zero checksum for new checksum
	sll $t0 $t0 16		# Realign original word
	and $t0 $t0 $t1		# Place new TTL in word
	sw $t0 8($a0)		# Replace word in packet with new TTL and zero'd checksum
calculateChecksum:	
	lw $t0 0($a0)		# Load first word
	sll $t0 $t0 4		# Isolate header length
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
	sll $t2 $t2 8		# Move byte into big endianness
	and $t0 $t0 $t2		# Add first byte of checksum into packet
	andi $t2 $t1 0x0000ff00 # Isolate second byte of half-word
	srl $t2 $t2 8		# Move byte into big endianness
	and $t0 $t0 $t2		# Add second byte of checksum into packet
	sw $t0 8($a0)		# Update the packet, ready to forward
	li $v0 1		# $v0 <- 1
	add $v1 $a0 $0		# $v1 <- $a0
exit:
	jr $ra
