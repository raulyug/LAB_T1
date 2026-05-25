import struct
import random
import socket
import ssl

def build_dns_query(domain: str) -> bytes:
    """[Tua função original - mantida idêntica]"""
    packet_id = random.randint(0, 65535)
    flags = 0x0100
    qdcount = 1
    ancount = 0
    nscount = 0
    arcount = 0
    
    header = struct.pack("!HHHHHH", packet_id, flags, qdcount, ancount, nscount, arcount)
    
    qname = b""
    for part in domain.split("."):
        qname += struct.pack("!B", len(part)) + part.encode('ascii')
    qname += b"\x00"
    
    qtype = 1
    qclass = 1
    question_tail = struct.pack("!HH", qtype, qclass)
    
    return header + qname + question_tail


def send_dns_query(packet: bytes, server_ip: str) -> bytes:
    """
    ABRE O CANAL DE REDE: Envia o pacote via UDP na porta 53 e aguarda a resposta.
    """
    # Cria um socket UDP (AF_INET = IPv4, SOCK_DGRAM = UDP)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3.0) # Se o servidor não responder em 3s, desiste
    
    try:
        # Envia o pacote binário para o IP escolhido na porta 53 (DNS tradicional)
        sock.sendto(packet, (server_ip, 53))
        
        # Recebe a resposta do servidor (bufsize de 1024 bytes é mais que suficiente)
        response, _ = sock.recvfrom(1024)
        return response
    finally:
        sock.close()

# DNT DOT para colocar prefixo de 2 bytes antes da mensagem, é só para rodar com o wireshark 
def send_dns_dot_query(packet: bytes, server_host: str, server_ip: str) -> bytes:
    """
    PARTE 3 - ENVIAR VIA DoT (PORTA 853 VIA TCP + TLS)
    """
    # 1. A regra da RFC 7858: Pegar o tamanho da query e transformar em 2 bytes
    query_length = len(packet)
    prefixo_tamanho = struct.pack("!H", query_length)
    
    # Payload final que vai rodar no canal seguro: [Tamanho (2B)] + [Query Binária]
    payload_dot = prefixo_tamanho + packet

    # 2. Configurar o contexto TLS seguro do Python
    context = ssl.create_default_context()
    
    # 3. Abrir o socket TCP tradicional na porta 853
    sock_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock_tcp.settimeout(4.0)
    
    # 4. Envelopar o socket TCP com a camada criptográfica TLS
    secure_sock = context.wrap_socket(sock_tcp, server_hostname=server_host)
    
    try:
        # Conecta no IP do servidor seguro
        secure_sock.connect((server_ip, 853))
        
        # Envia o pacote com os 2 bytes de prefixo instalados
        secure_sock.sendall(payload_dot)
        
        # A resposta TCP/DoT também vem com 2 bytes de tamanho no começo
        # Lemos os primeiros 2 bytes para saber o tamanho da resposta vindo
        response_len_bytes = secure_sock.recv(2)
        if not response_len_bytes:
            raise Exception("Nenhum dado recebido do servidor DoT.")
            
        response_len = struct.unpack("!H", response_len_bytes)[0]
        
        # Agora lemos o resto dos bytes da resposta baseados no tamanho descoberto
        response = secure_sock.recv(response_len)
        return response
        
    finally:
        secure_sock.close()


def parse_dns_response(response: bytes, query_packet: bytes) -> dict:
    """
    DESMONTA A RESPOSTA: Lê os bytes recebidos e extrai o RCODE e o IP.
    """
    # 1. Parse do Cabeçalho (Primeiros 12 bytes)
    header = response[:12]
    packet_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", header)
    
    # Extrai o RCODE (os 4 bits menos significativos das flags)
    rcode = flags & 0x000F
    
    # Mapeamento básico de erros de censura/status
    rcode_status = "OK"
    if rcode == 3: rcode_status = "NXDOMAIN"
    elif rcode == 5: rcode_status = "REFUSED"
    elif rcode != 0: rcode_status = f"ERRO_RCODE_{rcode}"
    
    # Se o servidor deu erro de cara, não adianta ler o resto
    if rcode != 0:
        return {"status": rcode_status, "ips": []}
        
    # 2. Pular a Seção Question (ela vem repetida na resposta)
    # Como sabemos o tamanho exato da nossa query, a resposta da Answer começa logo após ela!
    offset = len(query_packet)
    
    ips = []
    
    # 3. Parsear a Seção Answer (Registros de Resposta)
    # Vamos ler a quantidade de registros indicada por 'ancount'
    for _ in range(ancount):
        if offset >= len(response):
            break
            
        # O registro começa com o NAME (geralmente um ponteiro de 2 bytes 0xc000)
        # Vamos ler os primeiros 2 bytes para checar se é um ponteiro comprimido
        name_pointer = struct.unpack("!H", response[offset:offset+2])[0]
        if (name_pointer & 0xC000) == 0xC000:
            offset += 2 # Avança o ponteiro
        else:
            # Se não for ponteiro, teríamos que ler string por string até o \x00
            while response[offset] != 0:
                offset += 1
            offset += 1
            
        # Lê os campos fixos do registro (TYPE: 2B, CLASS: 2B, TTL: 4B, RDLENGTH: 2B)
        rtype, rclass, rttl, rdlength = struct.unpack("!HHIH", response[offset:offset+10])
        offset += 10
        
        # Se for do Tipo 1 (Registro A / IPv4), extrai o IP de 4 bytes
        if rtype == 1:
            ip_bytes = response[offset:offset+rdlength]
            # Converte os 4 bytes brutos no formato string "X.X.X.X"
            ip_str = socket.inet_ntoa(ip_bytes)
            ips.append(ip_str)
            
        offset += rdlength # Avança para o próximo registro
        
    return {"status": rcode_status, "ips": ips}


def main():
    domain = "www.example.com"
    # Servidor da Cloudflare que aceita DoT
    server_host = "one.one.one.one"
    server_ip = "1.1.1.1"
    
    print(f"--- Testando DoT para {domain} ---")
    query = build_dns_query(domain)
    try:
        response = send_dns_dot_query(query, server_host, server_ip)
        result = parse_dns_response(response, query)
        print(f"Resultado DoT: {result['status']} | IPs: {result['ips']}")
    except Exception as e:
        print(f"Erro no DoT: {e}")

if __name__ == "__main__":
    main()