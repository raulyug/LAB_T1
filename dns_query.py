import struct
import random

def build_dns_query(domain: str) -> bytes:
    """
    Constrói um pacote de consulta DNS (Query) em formato binário
    estritamente de acordo com a RFC 1035.
    
    Args:
        domain (str): O domínio a ser consultado (ex: 'www.pucrs.br').
        
    Returns:
        bytes: O pacote de consulta DNS no formato binário.
    """
    # ==========================================
    # 1. Cabeçalho (Header) - 12 bytes
    # ==========================================
    # ID: 16 bits (Aleatório)
    packet_id = random.randint(0, 65535)
    
    # Flags: 16 bits
    # QR(1 bit) | Opcode(4 bits) | AA(1 bit) | TC(1 bit) | RD(1 bit) || RA(1 bit) | Z(3 bits) | RCODE(4 bits)
    # Consulta (QR=0), Standard Query (Opcode=0), Recursion Desired (RD=1)
    # Binário: 0 0000 0 0 1 | 0 000 0000 -> 0x0100
    flags = 0x0100
    
    # Contadores (16 bits cada)
    qdcount = 1  # Question Count: 1
    ancount = 0  # Answer Record Count: 0
    nscount = 0  # Authority Record Count: 0
    arcount = 0  # Additional Record Count: 0
    
    # Empacota o cabeçalho (Formato: ! = Network/Big-Endian, H = unsigned short/2 bytes)
    header = struct.pack("!HHHHHH", packet_id, flags, qdcount, ancount, nscount, arcount)
    
    # ==========================================
    # 2. Seção de Pergunta (Question)
    # ==========================================
    # QNAME: Labels de tamanho (ex: www.pucrs.br -> \x03www\x05pucrs\x02br\x00)
    qname = b""
    for part in domain.split("."):
        # Adiciona o byte de tamanho e depois a string codificada em ASCII
        qname += struct.pack("!B", len(part)) + part.encode('ascii')
    qname += b"\x00"  # Terminador do QNAME (raiz)
    
    # QTYPE: 16 bits - Tipo A (IPv4 address) = 1
    qtype = 1
    
    # QCLASS: 16 bits - IN (Internet) = 1
    qclass = 1
    
    # Empacota o final da question
    question_tail = struct.pack("!HH", qtype, qclass)
    
    # Retorna o pacote completo concatenado
    return header + qname + question_tail

def main():
    domain = "www.pucrs.br"
    print(f"--- Construindo pacote DNS Query para: {domain} ---")
    
    try:
        dns_packet = build_dns_query(domain)
        
        print("\n[Pacote DNS em Hexadecimal]")
        hex_data = dns_packet.hex()
        # Formata para exibir em blocos de 2 bytes (4 caracteres hex)
        formatted_hex = " ".join(hex_data[i:i+4] for i in range(0, len(hex_data), 4))
        print(formatted_hex.upper())
        
        print(f"\n[Detalhes]")
        print(f"Tamanho total do pacote: {len(dns_packet)} bytes")
        print(f"Cabeçalho: {len(dns_packet) - len(domain) - 6} bytes (12 bytes padrão)")
        
    except Exception as e:
        print(f"Erro ao construir o pacote DNS: {e}")

if __name__ == "__main__":
    main()
