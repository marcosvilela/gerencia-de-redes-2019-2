#!/bin/python

import socket
import sys
import binascii

def formata_oid(OID_input):
	
	OID_tmp = OID_input.replace('.','')[2:]

	oid = chr(0x2b)
	for i in OID_tmp:
		oid = oid + chr(int(i))

	return oid

def monta_snmp(oid):
	val = chr(0x05) + chr(0x00)
	len_oid = len(oid)
	
	#Objeto
	type_oid = chr(0x06)	
	_oid = type_oid + chr(len_oid) + oid
	
	#Varbind
	type_var_bind = chr(0x30)
	var_bind = type_var_bind + chr(len_oid + 2 + 2) + _oid + val
	
	#Varbind list
	type_var_bind_list = chr(0x30)
	var_bind_list = type_var_bind_list + chr(len(var_bind)) + var_bind

	#Request ID, Error, ErrorIndex
	RqID = chr(2) + chr(1) + chr(1)
	Err = chr(2) + chr(1) + chr(0)
	ErrIndex = chr(2) + chr(1) + chr(0)

	SPDU = chr(0xa0) + chr(3 + 3 + 3 + len(var_bind_list)) + RqID + Err + ErrIndex + var_bind_list
	
	##Community, mantemos travado em public
	community = 'public'
	len_community = len(community)
	comm = chr(4) + chr(len_community) + community

	versao = chr(2) + chr(1) + chr(0)
	
	##Snmp Message
	msg_type = chr(0x30)
	snmp = msg_type + chr(3 + 2 + len_community + len(SPDU)) + versao + comm + SPDU
	return snmp

def desmonta_snmp(msg):	
	msg_list = list(msg)

	print msg_list

	snmp_value_type = ord(msg_list[0])
	snmp_value_length = ord(msg_list[1])
	snmp_version = ord(msg_list[4])
	snmp_community_length = ord(msg_list[7])
	snmp_community = msg_list[8:8+int(snmp_community_length)]

	snmp_pdu_size = ord(msg_list[8+int(snmp_community_length)+1])
	snmp_requst_id = ord(msg_list[8+int(snmp_community_length)+4])
	snmp_error = ord(msg_list[8+int(snmp_community_length)+7])
	snmp_error_index = ord(msg_list[8+int(snmp_community_length)+10])
	
	snmp_varbind_list_size = ord(msg_list[8+int(snmp_community_length)+12])
	snmp_varbind_size = ord(msg_list[8+int(snmp_community_length)+14])

	snmp_oid_size = ord(msg_list[8+int(snmp_community_length)+16])
	snmp_oid = '.'.join(list(map(lambda x:str(ord(x)), msg_list[8+int(snmp_community_length)+17:8+int(snmp_community_length)+17+snmp_oid_size])))

	snmp_value_size = ord(msg_list[8+int(snmp_community_length)+17+snmp_oid_size+1])
	snmp_value = ''.join(msg_list[8+int(snmp_community_length)+17+snmp_oid_size+2:])

	print "SNMP Message Type: " + str(snmp_value_type)
	print "SNMP Message Length: " + str(snmp_value_length)
	print "SNMP Version: " + str(snmp_version)
	print "SNMP Community: " + ''.join(snmp_community)
	print ""
	print "PDU Size: " + str(snmp_pdu_size)
	print "Request Id: " + str(snmp_requst_id)
	print "Error: " + str(snmp_error)
	print "Error Index: " + str(snmp_error_index)
	print ""
	print "Varbind List Size: " + str(snmp_varbind_list_size)
	print "Varbind Size: " + str(snmp_varbind_size)
	print ""
	print "OID Size: " + str(snmp_oid_size)
	print "OID: " + snmp_oid
	print ""
	print "Value Size: " + str(snmp_value_size)
	print "Value: " + str(snmp_value)
	

def send_socket_message(message, host='127.0.0.1'):
	
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.settimeout(10)

	s.sendto(message, (host, 161))
	print "Quadro enviado... Aguardando resposta" 

	while True:
		
		try:
			rx_buf = s.recv(2000)
			print "Recebido!" 
			return rx_buf

		except socket.timeout:
			print "Timed out!" 
			exit()
		S = rx_buf[0]
		break

	s.close()

	


if __name__ == '__main__':

	if len(sys.argv) < 3:
		print "Numero incorreto de argumentos" 
		print "Execute novamente no formato: pysnmp.py host oid [oid...]" 
		exit(-1)


	for oid_input in sys.argv[2:]:

		print "Enviando oid: " + str(oid_input)
		oid = formata_oid(oid_input)
		snmp_message = monta_snmp(oid)
		print "SNMP Message: " + str(list(snmp_message))
		result=send_socket_message(snmp_message, host=sys.argv[1])
		desmonta_snmp(result)
