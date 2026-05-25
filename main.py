import sys
import argparse
import csv
import time
from dns_query import build_dns_query, send_dns_query, parse_dns_response, send_dns_query_dot

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
        "DNS Provedor Local (Claro/Vivo)": "200.215.1.1",
        "Mullvad DNS": "194.242.2.2",
        "Freenom World": "80.80.80.80"
    }
}

SERVIDORES_DOT = {
    "Google Public DNS": "8.8.8.8",
    "Cloudflare":        "1.1.1.1",
    "Quad9":             "9.9.9.9",
}

DOMINIOS_TESTE = [
    "www.example.com",
    "www.pucrs.br",
    "internetbadguys.com",
    "reddit.com",
    "tinder.com",
    "polymarket.com",
    "youtube.com",
    "bet365.com",
    "piratebay.org"
]

# Consulta todos os servidores DNS para um domínio e detecta bloqueios ou anomalias.
def rodar_auditoria_bloqueio(dominio_alvo):
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

# Mede a latência UDP de um servidor com N consultas e retorna média, mínimo, máximo e taxa de perda.
def medir_latencia_servidor(nome: str, ip: str, categoria: str,
                             dominio: str = "www.example.com",
                             n_queries: int = 10) -> dict:
    latencias = []
    falhas = 0

    for i in range(n_queries):
        print(f"    [{i+1}/{n_queries}] ", end="", flush=True)
        query = build_dns_query(dominio)
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
        "categoria":   categoria,
        "servidor":    nome,
        "ip_servidor": ip,
        "avg_ms":      avg_ms,
        "min_ms":      min_ms,
        "max_ms":      max_ms,
        "perda_pct":   perda_pct,
    }


# Executa o benchmark de latência em todos os servidores e retorna a lista ordenada por desempenho.
def rodar_benchmark_latencia(n_queries: int = 10) -> list:
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

    resultados.sort(key=lambda r: r["avg_ms"] if r["avg_ms"] is not None else float("inf"))

    for i, r in enumerate(resultados, start=1):
        r["ranking"] = i

    return resultados


# Mede a latência DoT de um servidor com N consultas e registra também os bytes de aplicação trafegados.
def medir_latencia_dot(nome: str, ip: str,
                        dominio: str = "www.example.com",
                        n_queries: int = 10) -> dict:
    latencias = []
    bytes_totais = []
    falhas = 0

    for i in range(n_queries):
        print(f"    [DoT {i+1}/{n_queries}] ", end="", flush=True)
        query = build_dns_query(dominio)
        t0 = time.perf_counter()
        try:
            response = send_dns_query_dot(query, ip)
            t1 = time.perf_counter()
            ms = (t1 - t0) * 1000.0
            latencias.append(ms)
            bytes_totais.append(2 + len(query) + 2 + len(response))
            print(f"{ms:.1f}ms  ({2 + len(query) + 2 + len(response)}B)", flush=True)
        except Exception as e:
            falhas += 1
            print(f"FALHA ({e})", flush=True)

    perda_pct = (falhas / n_queries) * 100.0
    return {
        "servidor":      nome,
        "ip_servidor":   ip,
        "dot_avg_ms":    sum(latencias) / len(latencias) if latencias else None,
        "dot_min_ms":    min(latencias) if latencias else None,
        "dot_max_ms":    max(latencias) if latencias else None,
        "dot_perda_pct": perda_pct,
        "dot_bytes_avg": sum(bytes_totais) / len(bytes_totais) if bytes_totais else None,
    }


# Compara a latência UDP e DoT dos servidores definidos em SERVIDORES_DOT e retorna os resultados.
def rodar_comparacao_udp_dot(n_queries: int = 10) -> list:
    DOMINIO = "www.example.com"

    print(f"\n{'='*60}")
    print(f" Comparação UDP × DoT — Domínio: {DOMINIO}")
    print(f" {n_queries} consultas por protocolo por servidor")
    print(f"{'='*60}")

    resultados = []

    for nome, ip in SERVIDORES_DOT.items():
        print(f"\n{'─'*50}")
        print(f" {nome} ({ip})")

        print(f"\n  [UDP] Medindo...")
        udp = medir_latencia_servidor(nome, ip, "Sem Filtragem",
                                       dominio=DOMINIO, n_queries=n_queries)

        q = build_dns_query(DOMINIO)
        try:
            r = send_dns_query(q, ip)
            udp_bytes = len(q) + len(r)
        except Exception:
            udp_bytes = None

        if udp["avg_ms"] is not None:
            print(f"  >> UDP avg={udp['avg_ms']:.1f}ms  min={udp['min_ms']:.1f}ms  "
                  f"max={udp['max_ms']:.1f}ms  bytes={udp_bytes}")
        else:
            print(f"  >> UDP: 100% de perda")

        print(f"\n  [DoT] Medindo...")
        dot = medir_latencia_dot(nome, ip, dominio=DOMINIO, n_queries=n_queries)

        if dot["dot_avg_ms"] is not None:
            print(f"  >> DoT avg={dot['dot_avg_ms']:.1f}ms  min={dot['dot_min_ms']:.1f}ms  "
                  f"max={dot['dot_max_ms']:.1f}ms  bytes_avg={dot['dot_bytes_avg']:.0f}")
        else:
            print(f"  >> DoT: 100% de falhas")

        overhead_ms = (
            round(dot["dot_avg_ms"] - udp["avg_ms"], 2)
            if dot["dot_avg_ms"] is not None and udp["avg_ms"] is not None
            else None
        )

        resultados.append({
            "servidor":        nome,
            "ip_servidor":     ip,
            "udp_avg_ms":      udp["avg_ms"],
            "udp_min_ms":      udp["min_ms"],
            "udp_max_ms":      udp["max_ms"],
            "udp_perda_pct":   udp["perda_pct"],
            "udp_bytes":       udp_bytes,
            "dot_avg_ms":      dot["dot_avg_ms"],
            "dot_min_ms":      dot["dot_min_ms"],
            "dot_max_ms":      dot["dot_max_ms"],
            "dot_perda_pct":   dot["dot_perda_pct"],
            "dot_bytes_avg":   dot["dot_bytes_avg"],
            "overhead_lat_ms": overhead_ms,
        })

    return resultados


# Salva os resultados da comparação UDP × DoT no arquivo comparacao_udp_dot.csv.
def salvar_comparacao_csv(resultados: list) -> None:
    campos = [
        "servidor", "ip_servidor",
        "udp_avg_ms", "udp_min_ms", "udp_max_ms", "udp_perda_pct", "udp_bytes",
        "dot_avg_ms", "dot_min_ms", "dot_max_ms", "dot_perda_pct", "dot_bytes_avg",
        "overhead_lat_ms",
    ]

    def fmt(v, casas=2):
        return f"{v:.{casas}f}" if v is not None else "N/A"

    rows = []
    for r in resultados:
        rows.append({
            "servidor":        r["servidor"],
            "ip_servidor":     r["ip_servidor"],
            "udp_avg_ms":      fmt(r["udp_avg_ms"]),
            "udp_min_ms":      fmt(r["udp_min_ms"]),
            "udp_max_ms":      fmt(r["udp_max_ms"]),
            "udp_perda_pct":   fmt(r["udp_perda_pct"], 1),
            "udp_bytes":       r["udp_bytes"] if r["udp_bytes"] is not None else "N/A",
            "dot_avg_ms":      fmt(r["dot_avg_ms"]),
            "dot_min_ms":      fmt(r["dot_min_ms"]),
            "dot_max_ms":      fmt(r["dot_max_ms"]),
            "dot_perda_pct":   fmt(r["dot_perda_pct"], 1),
            "dot_bytes_avg":   fmt(r["dot_bytes_avg"], 0),
            "overhead_lat_ms": fmt(r["overhead_lat_ms"]),
        })

    with open("comparacao_udp_dot.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=campos)
        writer.writeheader()
        writer.writerows(rows)

    print(f"\n[SUCESSO] Comparação UDP × DoT salva em 'comparacao_udp_dot.csv'!")


# Salva o ranking do benchmark de latência no arquivo resultados.csv.
def salvar_benchmark_csv(resultados: list) -> None:
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


# Salva os resultados da auditoria de bloqueio no arquivo auditoria_bloqueio.csv.
def salvar_csv(todos_resultados):
    campos = ["dominio", "categoria", "servidor", "ip_servidor", "status_rcode", "ips_retornados"]
    with open("auditoria_bloqueio.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=campos)
        writer.writeheader()
        writer.writerows(todos_resultados)
    print(f"\n[SUCESSO] Todos os dados brutos foram salvos em 'auditoria_bloqueio.csv'!")

# Ponto de entrada: interpreta os argumentos e chama o modo correspondente.
def main():
    parser = argparse.ArgumentParser(description="Ferramenta de Auditoria DNS - LabRedes PUCRS")
    parser.add_argument("--domain", type=str, help="Domínio customizado para testar fora da lista padrão")
    parser.add_argument("--benchmark", action="store_true",
                        help="Executa benchmark de latência (10 consultas/servidor) para www.example.com "
                             "e salva o ranking em resultados.csv")
    parser.add_argument("--dot", action="store_true",
                        help="Compara latência UDP × DoT para Google, Cloudflare e Quad9 "
                             "(dados para a Seção 5.1 do relatório) → comparacao_udp_dot.csv")
    args = parser.parse_args()

    if args.dot:
        resultados = rodar_comparacao_udp_dot(n_queries=10)

        print("\n" + "=" * 88)
        print(" COMPARAÇÃO UDP × DoT — SEÇÃO 5.1 DO RELATÓRIO")
        print("=" * 88)
        print(f"{'Servidor':<25} {'UDP Avg(ms)':<14} {'DoT Avg(ms)':<14} {'Overhead(ms)':<15} {'Bytes UDP':<12} {'Bytes DoT'}")
        print("-" * 88)
        for r in resultados:
            udp = f"{r['udp_avg_ms']:.1f}" if r["udp_avg_ms"] is not None else "N/A"
            dot = f"{r['dot_avg_ms']:.1f}" if r["dot_avg_ms"] is not None else "N/A"
            ovh = f"+{r['overhead_lat_ms']:.1f}" if r["overhead_lat_ms"] is not None else "N/A"
            bu  = str(r["udp_bytes"]) if r["udp_bytes"] is not None else "N/A"
            bd  = f"{r['dot_bytes_avg']:.0f}" if r["dot_bytes_avg"] is not None else "N/A"
            print(f"{r['servidor']:<25} {udp:<14} {dot:<14} {ovh:<15} {bu:<12} {bd}")
        print("=" * 88)

        salvar_comparacao_csv(resultados)

    elif args.benchmark:
        resultados = rodar_benchmark_latencia(n_queries=10)

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
        todos_dados = rodar_auditoria_bloqueio(args.domain)
        salvar_csv(todos_dados)

    else:
        print("Iniciando auditoria completa de domínios para o relatório técnico...")
        todos_dados = []
        for dom in DOMINIOS_TESTE:
            resultados_dom = rodar_auditoria_bloqueio(dom)
            todos_dados.extend(resultados_dom)
            time.sleep(0.5)

        salvar_csv(todos_dados)

if __name__ == "__main__":
    main()
