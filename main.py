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
        "DNS Provedor Local (RLNET/PUCRS)": "200.215.1.1", # Ajuste se souber o seu, ou use um público alternativo
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

def medir_latencia_servidor(nome: str, ip: str, categoria: str,
                             dominio: str = "www.example.com",
                             n_queries: int = 10) -> dict:
    """Envia n_queries consultas DNS para o servidor e mede a latência de cada uma."""
    latencias = []
    falhas = 0

    for i in range(n_queries):
        print(f"    [{i+1}/{n_queries}] ", end="", flush=True)
        query = build_dns_query(dominio)   # rebuild para gerar packet_id único por consulta
        t0 = time.perf_counter()
        try:
            send_dns_query(query, ip)
            t1 = time.perf_counter()
            ms = (t1 - t0) * 1000.0
            latencias.append(ms)
            print(f"{ms:.1f}ms", flush=True)
        except Exception:
            falhas += 1
            print("TIMEOUT", flush=True)

    perda_pct = (falhas / n_queries) * 100.0
    avg_ms = sum(latencias) / len(latencias) if latencias else None
    min_ms = min(latencias) if latencias else None
    max_ms = max(latencias) if latencias else None

    return {
        "categoria":  categoria,
        "servidor":   nome,
        "ip_servidor": ip,
        "avg_ms":     avg_ms,
        "min_ms":     min_ms,
        "max_ms":     max_ms,
        "perda_pct":  perda_pct,
    }


def rodar_benchmark_latencia(n_queries: int = 10) -> list:
    """Executa o benchmark de latência para www.example.com em todos os servidores,
    calcula estatísticas e retorna a lista ordenada por desempenho (ranking)."""
    DOMINIO_CONTROLE = "www.example.com"

    print(f"\n{'='*58}")
    print(f" Benchmark de Latência DNS — Domínio: {DOMINIO_CONTROLE}")
    print(f" {n_queries} consultas por servidor")
    print(f"{'='*58}")

    resultados = []

    for categoria, servidores in SERVIDORES_DNS.items():
        print(f"\n> Categoria: {categoria}")
        for nome, ip in servidores.items():
            print(f"\n  Medindo [{nome} - {ip}]...")
            r = medir_latencia_servidor(nome, ip, categoria,
                                        dominio=DOMINIO_CONTROLE,
                                        n_queries=n_queries)
            if r["avg_ms"] is not None:
                print(f"  >> avg={r['avg_ms']:.1f}ms  min={r['min_ms']:.1f}ms  "
                      f"max={r['max_ms']:.1f}ms  perda={r['perda_pct']:.0f}%")
            else:
                print(f"  >> 100% de perda de pacotes")
            resultados.append(r)

    # Ordena do mais rápido ao mais lento; servidores com 100% de perda vão ao final
    resultados.sort(key=lambda r: r["avg_ms"] if r["avg_ms"] is not None else float("inf"))

    # Atribui ranking (1 = mais rápido)
    for i, r in enumerate(resultados, start=1):
        r["ranking"] = i

    return resultados


def salvar_benchmark_csv(resultados: list) -> None:
    """Salva os resultados do benchmark de latência em resultados.csv."""
    campos = [
        "ranking", "categoria", "servidor", "ip_servidor",
        "tempo_medio_ms", "tempo_min_ms", "tempo_max_ms", "perda_pacotes_pct"
    ]
    rows = []
    for r in resultados:
        rows.append({
            "ranking":           r["ranking"],
            "categoria":         r["categoria"],
            "servidor":          r["servidor"],
            "ip_servidor":       r["ip_servidor"],
            "tempo_medio_ms":    f"{r['avg_ms']:.2f}" if r["avg_ms"] is not None else "N/A",
            "tempo_min_ms":      f"{r['min_ms']:.2f}" if r["min_ms"] is not None else "N/A",
            "tempo_max_ms":      f"{r['max_ms']:.2f}" if r["max_ms"] is not None else "N/A",
            "perda_pacotes_pct": f"{r['perda_pct']:.1f}",
        })

    with open("resultados.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=campos)
        writer.writeheader()
        writer.writerows(rows)

    print(f"\n[SUCESSO] Benchmark de latência salvo em 'resultados.csv'!")


def salvar_csv(todos_resultados):
    """Salva os dados brutos no auditoria_bloqueio.csv"""
    campos = ["dominio", "categoria", "servidor", "ip_servidor", "status_rcode", "ips_retornados"]
    with open("auditoria_bloqueio.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=campos)
        writer.writeheader()
        writer.writerows(todos_resultados)
    print(f"\n[SUCESSO] Todos os dados brutos foram salvos em 'auditoria_bloqueio.csv'!")

def main():
    parser = argparse.ArgumentParser(description="Ferramenta de Auditoria DNS - LabRedes PUCRS")
    parser.add_argument("--domain", type=str, help="Domínio customizado para testar fora da lista padrão")
    parser.add_argument("--benchmark", action="store_true",
                        help="Executa benchmark de latência (10 consultas/servidor) para www.example.com "
                             "e salva o ranking em resultados.csv")
    args = parser.parse_args()

    if args.benchmark:
        # ── Modo Benchmark de Latência ──────────────────────────────────────
        resultados = rodar_benchmark_latencia(n_queries=10)

        # Exibe tabela final com o ranking completo no console
        print("\n" + "=" * 90)
        print(" RANKING FINAL DE LATÊNCIA DNS")
        print("=" * 90)
        print(f"{'#':<4} {'Servidor':<35} {'IP':<18} {'Avg (ms)':<11} {'Min (ms)':<11} {'Max (ms)':<11} {'Perda %'}")
        print("-" * 90)
        for r in resultados:
            avg = f"{r['avg_ms']:.1f}" if r["avg_ms"] is not None else "N/A"
            mn  = f"{r['min_ms']:.1f}" if r["min_ms"] is not None else "N/A"
            mx  = f"{r['max_ms']:.1f}" if r["max_ms"] is not None else "N/A"
            print(f"{r['ranking']:<4} {r['servidor']:<35} {r['ip_servidor']:<18} "
                  f"{avg:<11} {mn:<11} {mx:<11} {r['perda_pct']:.1f}%")
        print("=" * 90)

        salvar_benchmark_csv(resultados)

    elif args.domain:
        # ── Modo domínio customizado ─────────────────────────────────────────
        todos_dados = rodar_auditoria_bloqueio(args.domain)
        salvar_csv(todos_dados)

    else:
        # ── Modo auditoria completa (padrão) ─────────────────────────────────
        print("Iniciando auditoria completa de domínios para o relatório técnico...")
        todos_dados = []
        for dom in DOMINIOS_TESTE:
            resultados_dom = rodar_auditoria_bloqueio(dom)
            todos_dados.extend(resultados_dom)
            time.sleep(0.5)  # Evita sobrecarregar as requisições sequenciais

        salvar_csv(todos_dados)

if __name__ == "__main__":
    main()