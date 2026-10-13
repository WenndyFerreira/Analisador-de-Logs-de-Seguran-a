Readme.txt

🛡️ Analisador de Logs de Segurança

### Projeto acadêmico | Python | Segurança da Informação

## 📌 Sobre o projeto

O **Analisador de Logs de Segurança** é um projeto desenvolvido em Python com o objetivo de analisar registros de autenticação, identificar comportamentos suspeitos e gerar relatórios para auxiliar na investigação de possíveis incidentes de segurança.

O sistema realiza a leitura de arquivos de log, identifica tentativas de login bem-sucedidas e malsucedidas, contabiliza eventos por endereço IP e detecta padrões compatíveis com possíveis tentativas de ataques de força bruta.

Este projeto foi desenvolvido para fins educacionais, como parte do aprimoramento dos meus conhecimentos em **Python, Redes de Computadores e Segurança da Informação**.

## 🎯 Objetivos

- Aplicar conhecimentos de programação Python em um cenário de Segurança da Informação.
- Compreender a estrutura e a importância dos arquivos de log.
- Desenvolver técnicas básicas de análise de eventos.
- Identificar padrões de falhas de autenticação.
- Praticar manipulação de arquivos e tratamento de dados.
- Gerar relatórios estruturados para análise de segurança.

## ⚙️ Funcionalidades

**1. Leitura de logs**

Realiza a leitura de registros armazenados em arquivos `.log`, identificando data, horário, endereço IP e status de autenticação.

**2. Análise de autenticações**

Identifica e contabiliza eventos de autenticação classificados como `SUCESSO` ou `FALHA`.

**3. Identificação de IPs**

Agrupa os eventos por endereço IP e apresenta os endereços com maior quantidade de registros.

**4. Detecção de possíveis ataques de força bruta**

Analisa falhas de autenticação por endereço IP dentro de um intervalo de tempo configurável.

Na configuração inicial, o sistema gera um alerta quando identifica cinco ou mais falhas em uma janela de dez minutos.

**5. Validação dos registros**

Verifica o formato das linhas, valida endereços IP e ignora registros inválidos.

**6. Geração de relatórios**

Exporta os alertas identificados para um arquivo `.csv`, permitindo análises posteriores em ferramentas como Excel e Pandas.

## 🛠️ Tecnologias utilizadas

| Tecnologia | Aplicação |
|---|---|
| Python | Desenvolvimento da aplicação |
| re | Interpretação de registros com expressões regulares |
| csv | Exportação de relatórios |
| pathlib | Gerenciamento de caminhos de arquivos |
| collections | Contagem e agrupamento de eventos |
| datetime | Análise de datas e intervalos |
| ipaddress | Validação de endereços IP |
| VS Code | Ambiente de desenvolvimento |
| Git e GitHub | Versionamento e publicação |

O projeto utiliza bibliotecas da própria