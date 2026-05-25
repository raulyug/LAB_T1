import struct
import random
import socket
import ssl

# Monta o pacote DNS binário para o domínio informado e retorna os bytes da consulta.
def build_dns_query(domain: str) -> bytes:
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


# Envia o pacote DNS via UDP na porta 53 e retorna os bytes da resposta.
def send_dns_query(packet: bytes, server_ip: str) -> bytes:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3.0)

    try:
        sock.sendto(packet, (server_ip, 53))
        response, _ = sock.recvfrom(1024)
        return response
    finally:
        sock.close()


# Envia o pacote DNS via TCP+TLS (DoT) na porta 853 e retorna os bytes da resposta.
def send_dns_query_dot(packet: bytes, server_ip: str, port: int = 853) -> bytes:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_sock.settimeout(5.0)
    tls_sock = context.wrap_socket(raw_sock)

    try:
        tls_sock.connect((server_ip, port))

        mensagem = struct.pack("!H", len(packet)) + packet
        tls_sock.sendall(mensagem)

        raw_len = b""
        while len(raw_len) < 2:
            chunk = tls_sock.recv(2 - len(raw_len))
            if not chunk:
                raise ConnectionError("Conexão encerrada antes de receber o tamanho da resposta")
            raw_len += chunk

        resp_len = struct.unpack("!H", raw_len)[0]

        response = b""
        while len(response) < resp_len:
            chunk = tls_sock.recv(resp_len - len(response))
            if not chunk:
                raise ConnectionError("Resposta DoT incompleta")
            response += chunk

        return response
    finally:
        tls_sock.close()


# Interpreta os bytes da resposta DNS e retorna o status RCODE e os IPs encontrados.
def parse_dns_response(response: bytes, query_packet: bytes) -> dict:
    header = response[:12]
    packet_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", header)

    rcode = flags & 0x000F

    rcode_status = "OK"
    if rcode == 3: rcode_status = "NXDOMAIN"
    elif rcode == 5: rcode_status = "REFUSED"
    elif rcode != 0: rcode_status = f"ERRO_RCODE_{rcode}"

    if rcode != 0:
        return {"status": rcode_status, "ips": []}

    offset = len(query_packet)

    ips = []

    for _ in range(ancount):
        if offset >= len(response):
            break

        name_pointer = struct.unpack("!H", response[offset:offset+2])[0]
        if (name_pointer & 0xC000) == 0xC000:
            offset += 2
        else:
            while response[offset] != 0:
                offset += 1
            offset += 1

        rtype, rclass, rttl, rdlength = struct.unpack("!HHIH", response[offset:offset+10])
        offset += 10

        if rtype == 1:
            ip_bytes = response[offset:offset+rdlength]
            ip_str = socket.inet_ntoa(ip_bytes)
            ips.append(ip_str)

        offset += rdlength

    return {"status": rcode_status, "ips": ips}


# Realiza uma consulta de teste para www.pucrs.br e imprime o resultado no terminal.
def main():
    domain = "www.pucrs.br"
    server_ip = "8.8.8.8"

    print(f"--- 1. Construindo pacote para: {domain} ---")
    query_packet = build_dns_query(domain)

    print(f"--- 2. Enviando via UDP para o servidor: {server_ip} ---")
    try:
        response_packet = send_dns_query(query_packet, server_ip)
        print(f"Recebidos {len(response_packet)} bytes de resposta.")

        print(f"--- 3. Fazendo o Parsing dos bytes recebidos ---")
        result = parse_dns_response(response_packet, query_packet)

        print("\n================ RESULTADO ================")
        print(f"Status do Servidor (RCODE): {result['status']}")
        print(f"Endereços IP Retornados: {result['ips']}")
        print("===========================================")

    except socket.timeout:
        print("\n[TIMEOUT] O servidor DNS não respondeu a tempo.")
    except Exception as e:
        print(f"\n[ERRO] Falha no processo: {e}")

if __name__ == "__main__":
    main()
