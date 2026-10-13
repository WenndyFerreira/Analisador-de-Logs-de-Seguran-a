
import re
import csv
import ipaddress
from pathlib import Path
from collections import Counter, defaultdict
from datetime import datetime, timedelta

# ==========================================
# 1. CONFIGURAÇÕES DO SISTEMA
# ==========================================

PASTA_PROJETO = Path(__file__).resolve().parent

ARQUIVO_LOG = PASTA_PROJETO / "seguranca.log"
ARQUIVO_RELATORIO = PASTA_PROJETO / "relatorio_seguranca.csv"

LIMITE_FALHAS = 5
JANELA_MINUTOS = 10

# Formato esperado:
# 2026-10-13 10:30:00 | IP: 192.168.1.10 | STATUS: FALHA

PADRAO_LOG = re.compile(
    r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"
    r"\s*\|\s*IP:\s*(\S+)"
    r"\s*\|\s*STATUS:\s*(SUCESSO|FALHA)\s*$",
    re.IGNORECASE
)


# ==========================================
# 2. CRIAR LOG DE EXEMPLO
# ==========================================

def criar_log_exemplo():

    if ARQUIVO_LOG.exists():
        return

    agora = datetime.now().replace(microsecond=0)

    registros = [
        (-15, "192.168.1.10", "SUCESSO"),
        (-9, "192.168.1.20", "FALHA"),
        (-8, "192.168.1.20", "FALHA"),
        (-7, "192.168.1.20", "FALHA"),
        (-6, "192.168.1.20", "FALHA"),
        (-5, "192.168.1.20", "FALHA"),
        (-4, "192.168.1.20", "FALHA"),
        (-3, "192.168.1.30", "SUCESSO"),
        (-2, "192.168.1.40", "FALHA"),
        (-1, "192.168.1.40", "SUCESSO"),
    ]

    with open(ARQUIVO_LOG, "w", encoding="utf-8") as arquivo:

        for minutos, ip, status in registros:

            data = agora + timedelta(minutes=minutos)

            arquivo.write(
                f"{data:%Y-%m-%d %H:%M:%S} "
                f"| IP: {ip} | STATUS: {status}\n"
            )

    print("Arquivo de exemplo criado: seguranca.log")


# ==========================================
# 3. LER E VALIDAR OS LOGS
# ==========================================

def ler_logs():

    eventos = []
    linhas_invalidas = 0

    with open(ARQUIVO_LOG, "r", encoding="utf-8-sig") as arquivo:

        for numero_linha, linha in enumerate(arquivo, start=1):

            linha = linha.strip()

            if not linha:
                continue

            resultado = PADRAO_LOG.fullmatch(linha)

            if not resultado:
                linhas_invalidas += 1
                continue

            data_texto, ip, status = resultado.groups()

            try:
                data = datetime.strptime(
                    data_texto,
                    "%Y-%m-%d %H:%M:%S"
                )

                ipaddress.ip_address(ip)

            except ValueError:
                linhas_invalidas += 1
                continue

            eventos.append({
                "data": data,
                "ip": ip,
                "status": status.upper(),
                "linha": numero_linha
            })

    eventos.sort(key=lambda evento: evento["data"])

    return eventos, linhas_invalidas


# ==========================================
# 4. DETECTAR FALHAS CONSECUTIVAS
# ==========================================

def detectar_ataques(eventos):

    falhas_por_ip = defaultdict(list)

    for evento in eventos:

        if evento["status"] == "FALHA":

            falhas_por_ip[evento["ip"]].append(
                evento["data"]
            )

    alertas = []

    janela = timedelta(minutes=JANELA_MINUTOS)

    for ip, datas in falhas_por_ip.items():

        inicio = 0
        maior_quantidade = 0
        periodo_suspeito = None

        for fim in range(len(datas)):

            while datas[fim] - datas[inicio] > janela:
                inicio += 1

            quantidade = fim - inicio + 1

            if quantidade > maior_quantidade:

                maior_quantidade = quantidade

                periodo_suspeito = (
                    datas[inicio],
                    datas[fim]
                )

        if maior_quantidade >= LIMITE_FALHAS:

            alertas.append({
                "ip": ip,
                "falhas": maior_quantidade,
                "inicio": periodo_suspeito[0],
                "fim": periodo_suspeito[1],
                "classificacao": "Possível força bruta"
            })

    return sorted(
        alertas,
        key=lambda alerta: alerta["falhas"],
        reverse=True
    )


# ==========================================
# 5. ESTATÍSTICAS
# ==========================================

def gerar_estatisticas(eventos):

    total = len(eventos)

    sucessos = sum(
        1 for evento in eventos
        if evento["status"] == "SUCESSO"
    )

    falhas = sum(
        1 for evento in eventos
        if evento["status"] == "FALHA"
    )

    ips = Counter(
        evento["ip"]
        for evento in eventos
    )

    return {
        "total": total,
        "sucessos": sucessos,
        "falhas": falhas,
        "ips": ips
    }


# ==========================================
# 6. GERAR RELATÓRIO CSV
# ==========================================

def gerar_relatorio(alertas):

    with open(
        ARQUIVO_RELATORIO,
        "w",
        newline="",
        encoding="utf-8-sig"
    ) as arquivo:

        campos = [
            "IP",
            "Quantidade de falhas",
            "Início",
            "Fim",
            "Classificação"
        ]

        escritor = csv.DictWriter(
            arquivo,
            fieldnames=campos
        )

        escritor.writeheader()

        for alerta in alertas:

            escritor.writerow({
                "IP": alerta["ip"],
                "Quantidade de falhas": alerta["falhas"],
                "Início": alerta["inicio"].strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                "Fim": alerta["fim"].strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                "Classificação": alerta["classificacao"]
            })


# ==========================================
# 7. EXIBIR RESULTADOS
# ==========================================

def mostrar_resultados(eventos, invalidas):

    estatisticas = gerar_estatisticas(eventos)

    alertas = detectar_ataques(eventos)

    print("\n" + "=" * 55)
    print("        ANALISADOR DE LOGS DE SEGURANÇA")
    print("=" * 55)

    print(f"\nTotal de eventos: {estatisticas['total']}")
    print(f"Logins bem-sucedidos: {estatisticas['sucessos']}")
    print(f"Tentativas malsucedidas: {estatisticas['falhas']}")
    print(f"Linhas inválidas ignoradas: {invalidas}")
    print(f"IPs identificados: {len(estatisticas['ips'])}")

    print("\n--- IPs COM MAIS EVENTOS ---")

    for ip, quantidade in estatisticas["ips"].most_common(10):

        print(f"{ip}: {quantidade} evento(s)")

    print("\n--- ALERTAS DE SEGURANÇA ---")

    if not alertas:

        print("Nenhum padrão suspeito identificado.")

    else:

        for alerta in alertas:

            print(f"\nIP: {alerta['ip']}")
            print(f"Falhas na janela: {alerta['falhas']}")
            print(f"Classificação: {alerta['classificacao']}")
            print(f"Início: {alerta['inicio']}")
            print(f"Fim: {alerta['fim']}")

            print(
                "Recomendação: verificar a origem das "
                "tentativas, revisar os registros e "
                "considerar mecanismos de proteção "
                "contra tentativas repetidas."
            )

    gerar_relatorio(alertas)

    print("\nRelatório CSV gerado com sucesso!")
    print(f"Arquivo: {ARQUIVO_RELATORIO.name}")

    print("\nAnálise concluída.")


# ==========================================
# 8. EXECUÇÃO PRINCIPAL
# ==========================================

def main():

    print("Iniciando o Analisador de Logs...")

    criar_log_exemplo()

    try:

        eventos, invalidas = ler_logs()

        if not eventos:

            print(
                "Nenhum evento válido encontrado "
                "no arquivo de logs."
            )
            return

        mostrar_resultados(eventos, invalidas)

    except OSError as erro:

        print(f"Erro ao acessar os arquivos: {erro}")


if __name__ == "__main__":
    main()
