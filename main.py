import sys
import argparse
import csv
import time
from dns_query import build_dns_query, send_dns_query, parse_dns_response

# 1. Listas oficiais do enunciado do trabalho (mínimo de 16 servidores e 9 domínios)
SERVIDORES_DNS = {
    "Sem Filtragem": {
        "Google Public DNS": "8.8.8.8",
        "Google Public DNS (secundário)": "8.8.4.4",
        "Cloudflare": "1.1.1.1",
        "Cloudflare (secundário)": "1.0.0.1",
        "Quad9 (sem filtro)": "9.9.9.10",
        "Verisign": "64.6.64.6",
    },
    "Com Filtragem de Segurança": {
        "Quad9": "9.9.9.9",
        "OpenDNS": "208.67.222.222",
        "CleanBrowsing Security": "185.228.168.9",
        "AdGuard DNS": "94.140.14.14",
    },
    "Com Filtragem Familiar": {
        "Cloudflare Family": "1.1.1.3",
        "OpenDNS FamilyShield": "208.67.222.123",
        "CleanBrowsing Family": "185.228.168.168",
        "AdGuard Family": "94.140.14.15",
    },
    "Adicionais Escolhidos": {
        "Control D": "76.76.2.0",
        "Comodo Secure": "8.26.56.26",
        "DNS Provedor Local (Claro/Vivo)": "200.215.1.1", # Ajuste se souber o seu, ou use um público alternativo
        "Mullvad DNS": "194.242.2.2",
        "Freenom World": "80.80.80.80"
    }
}

DOMINIOS_TESTE = [
    "www.example.com",     # Controle
    "www.pucrs.br",        # Controle Regional
    "internetbadguys.com", # Bloqueado por Segurança
    "reddit.com",          # Familiar
    "tinder.com",          # Familiar
    "polymarket.com",      # Bloqueio Judicial Brasil
    "youtube.com",             # Adicional 1 (Familiar)
    "bet365.com",          # Adicional 2 (Potencial de bloqueio/regulação)
    "piratebay.org"        # Adicional 3 (Bloqueio de pirataria)
]

def rodar_auditoria_bloqueio(dominio_alvo):
    """Executa a verificação em todos os servidores para um domínio específico"""
    print(f"\n========================================================")
    print(f" Executando Auditoria de Bloqueio para: {dominio_alvo}")
    print(f"========================================================")
    
    resultados_dominio = []
    
    for categoria, servidores in SERVIDORES_DNS.items():
        print(f"\n> Categoria: {categoria}")
        for nome, ip in servidores.items():
            try:
                query = build_dns_query(dominio_alvo)
                resposta_bruta = send_dns_query(query, ip)
                dados = parse_dns_response(resposta_bruta, query)
                
                status = dados["status"]
                ips = dados["ips"]
                
                # Detecção simples de anomalias na tela
                alerta = ""
                if status != "OK":
                    alerta = f" [BLOQUEIO DETECTADO: {status}]"
                elif dominio_alvo == "internetbadguys.com" and "146.112." in "".join(ips):
                    alerta = " [BLOQUEIO OPENDNS: Redirecionado para IP de Aviso]"
                
                print(f"  [{nome} - {ip}]: Status: {status} | IPs: {ips}{alerta}")
                
                resultados_dominio.append({
                    "dominio": dominio_alvo,
                    "categoria": categoria,
                    "servidor": nome,
                    "ip_servidor": ip,
                    "status_rcode": status,
                    "ips_retornados": ", ".join(ips) if ips else "Nenhum"
                })
                
            except Exception as e:
                print(f"  [{nome} - {ip}]: FALHA/TIMEOUT de conexão.")
                resultados_dominio.append({
                    "dominio": dominio_alvo,
                    "categoria": categoria,
                    "servidor": nome,
                    "ip_servidor": ip,
                    "status_rcode": "TIMEOUT",
                    "ips_retornados": "Nenhum"
                })
                
    return resultados_dominio

def salvar_csv(todos_resultados):
    """Salva os dados brutos no resultados.csv"""
    campos = ["dominio", "categoria", "servidor", "ip_servidor", "status_rcode", "ips_retornados"]
    with open("resultados.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=campos)
        writer.writeheader()
        writer.writerows(todos_resultados)
    print(f"\n[SUCESSO] Todos os dados brutos foram salvos em 'resultados.csv'!")

def main():
    parser = argparse.ArgumentParser(description="Ferramenta de Auditoria DNS - LabRedes PUCRS")
    parser.add_argument("--domain", type=str, help="Domínio customizado para testar fora da lista padrão")
    args = parser.parse_args()

    todos_dados = []

    if args.domain:
        # Executa apenas para o domínio passado no argumento do terminal
        todos_dados = rodar_auditoria_bloqueio(args.domain)
        salvar_csv(todos_dados)
    else:
        # Executa a bateria completa do relatório de forma sequencial
        print("Iniciando auditoria completa de domínios para o relatório técnico...")
        for dom in DOMINIOS_TESTE:
            resultados_dom = rodar_auditoria_bloqueio(dom)
            todos_dados.extend(resultados_dom)
            time.sleep(0.5) # Evita sobrecarregar as requisições sequenciais
            
        salvar_csv(todos_dados)

if __name__ == "__main__":
    main()