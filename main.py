import os

def build_dns_query(domain: str) -> bytes:
    """
    Constrói um pacote de consulta DNS (Query) no formato binário estrito da RFC 1035.
    
    Args:
        domain (str): O domínio a ser consultado (ex: 'www.pucrs.br')
        
    Returns:
        bytes: O pacote DNS completo em formato binário
    """
    
    # ==========================================
    # 1. HEADER SECTION (12 bytes)
    # ==========================================
    # ID (Transaction ID): 16 bits (2 bytes) aleatórios para identificar a consulta
    transaction_id = os.urandom(2) 
    
    # FLAGS: 16 bits (2 bytes)
    # QR(1 bit)=0 (Query), Opcode(4 bits)=0000 (Standard Query), AA(1 bit)=0, TC(1 bit)=0, 
    # RD(1 bit)=1 (Recursion Desired), RA(1 bit)=0, Z(3 bits)=000, RCODE(4 bits)=0000
    # Em binário: 0000 0001 0000 0000 -> Em hexadecimal: 0x0100
    flags = b'\x01\x00'
    
    # QDCOUNT: 16 bits (2 bytes) - Número de entradas na seção Question (1)
    qdcount = b'\x00\x01'
    
    # ANCOUNT, NSCOUNT, ARCOUNT: 16 bits (2 bytes) cada - Respostas, Autoridades e Adicionais (todos 0)
    ancount = b'\x00\x00'
    nscount = b'\x00\x00'
    arcount = b'\x00\x00'
    
    header = transaction_id + flags + qdcount + ancount + nscount + arcount
    
    # ==========================================
    # 2. QUESTION SECTION
    # ==========================================
    # QNAME: Sequência de labels de tamanho (ex: 3www5pucrs2br0)
    qname = b''
    for part in domain.split('.'):
        # Converte o tamanho da parte em 1 byte e adiciona a string em ASCII
        qname += bytes([len(part)]) + part.encode('ascii')
    
    # Terminador nulo (label de tamanho 0 indicando o root)
    qname += b'\x00'
    
    # QTYPE: 16 bits (2 bytes) - Tipo de consulta: A (IPv4) = 1
    qtype = b'\x00\x01'
    
    # QCLASS: 16 bits (2 bytes) - Classe da consulta: IN (Internet) = 1
    qclass = b'\x00\x01'
    
    question = qname + qtype + qclass
    
    # ==========================================
    # PACOTE COMPLETO
    # ==========================================
    return header + question

if __name__ == '__main__':
    dom = 'www.pucrs.br'
    pacote = build_dns_query(dom)
    
    print(f"=== Pacote DNS Query para: {dom} ===")
    print(f"Formato bytes:\n{pacote}\n")
    print("Formato Hexadecimal:")
    print(" ".join(f"{b:02x}" for b in pacote))
