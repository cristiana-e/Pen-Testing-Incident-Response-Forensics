# Pen-Testing-Incident-Response-Forensics

## O que é Penetration Testing (Pentest)?

Teste de penetração são testes de seguranças que simulam ataques reais para identificar fraquezas e vulnerabilidades em aplicações, sitemas ou redes reais.

## Qual a importância do pentesting?

É de extrema importância que vulneradilidades sejam rastreadas regularmente para garantir a segurança das aplicações/redes, visto que ciberataques são cada vez mais recorrentes e perigosos.

Pentesting podem ser realizados em diversos sistemas operacionais OS.

<img width="216" alt="image" src="https://github.com/cristiana-e/Pen-Testing-Incident-Response-Forensics/assets/19941757/01e309b1-b2cb-4003-9b7f-7fffd5a90e40">

# Abordagens

## Funcionários Internos vs Hackers Externos

É importante testas esses sistemas e aplicações como se você fosse um funcionário ou ex funcionário que já teve acesso à determinadas informações e poderia penetrar muito mais a fundo na estrutura atacada por já conhecê-la.

## Verificações de Aplicações Web & Mobile

Visa verificar a segurança do código, quebrar as autenticações e senhas que possuírem vulnerabilidades.

## Engenharia Social

Também faz parte dos testes de penetração utilizar táticas de engenharia social para adquirir credenciais, acessos, informações e privilégios e, desta forma, conseguir escalar o ataque de maneira muito mais eficaz.

## Rede Wireless, dispositivos integrados e IoT

Testar as vulnerabilidade desses dispositivos que podem estar conectados à rede da empresa.

## ICS (Industry Control System) Penetration

Estes sistemas geralmente são ultrapassados em configurações e senhas.

# Metodologia Geral

- Planejamento
- Descoberta
- Ataque
- Relatório

## Planejamento

Nesta fase são definidos os objetivos, alvos e barreiras para o ataque. É importante frisar que tudo precisa estar acordado em um contrato detalhado sobre as abordagens que serão utilizadas. Também é definido até onde o ataque irá: se irá até ganhar acesso ao sistema, se irá mais a fundo. Tudo precisa ser cuidadosamente planejados pois estes sistemas e aplicações são reais e podem ser afetados por sua ação.

## Descoberta

Inúmeras abordagens podem ser utilizadas para adquirir informações.
- Análise de vulnerabilidade: realizar análises de vulnerabilidades para identificar a versão dos softwares, patches faltantes e erros de configurações. Ao identificar o SO, as versões dos softwares e aplicações que rodam nesse sistema, é possivel procurar vulnerabilidades já conhecidas para esses recursos.

- Dorks: Google Dork query, é uma forma de busca avançada do google para adquirir mais informações sobre um item. É possível obter informções que não são legíveis sobre um website.

  <img width="712" alt="image" src="https://github.com/cristiana-e/Pen-Testing-Incident-Response-Forensics/assets/19941757/7d7bd8a2-4da2-4a41-b335-fa398f6a7817">

- Formas passivas: É possível monitorar funcionários para tentar obter alguma informação ou credencial. Utilizar de Listeners no tráfego de rede da empresa para pbservar como as comunicações são feitas.

- Formas ativas: É possível mapear a rede, portas abertas para tentar encontrar formas de entrar no sistema, ou até mesmo quebrar senhas.

- Engenharia social: As vezes é necessários tentar fazer com que essas informações te sejam entregues.

### Ferramentas de scan


<img width="914" alt="image" src="https://github.com/cristiana-e/Pen-Testing-Incident-Response-Forensics/assets/19941757/68a080e4-c1cc-41db-af05-5a24f9689bc3">

## Métodos para ganhar acesso
### Passivo-Online
- Wire Sniffing: Captura os pacotes de dados através da internet
- Man in the Middle: sequestra uma sessão emt empo real para tentar ganhar acessos
- Replay Attack: Uma transmissão de dados válida é maliciosamente/fraudulemtamente repetida ou atrasada.

  ### Ativo-Online
  - Adivinhar as senhas: ataques de força bruta
  - Trojan/Spyware/Keylogger: softwares espiões que coletam diferentes tipos de dados
  - Injeção de Hash: Autentificar em um servidor ou serviço usando uma hash NTLM ou LanMan adjacente da senha do usuário. (Tentan entrar no arquivo da senha no servidor e tentar decodificá-lo)
  - Phishing: tentativa de enganar o usuário com um link malicioso que leva a instalação de umn malware, um ataque de ransomware ou roubo de informações.
 
  ### Ataques Offlines

  - Ataques pre-computados: Estrutura de dados que usa uma função hash para armazenar, ordenar ou acessar dados em um array.
  - Distributed Network Attack (DNA): sistema para crackear senhas
  - Rainbow: rainbow table é uma tabela pre computada para reverter funções hash criptográficas geralmente usadas para quebrar senhas.
 
  ### Ataques não eletrônicos
  - Engenharia social
  - Ataque dos ombros (Shoulder surfing): espiar por cima dos ombros alguém digitar suas credenciais
  - Dumpster diving: tentar recuperar informações que foram descartadas no lixo
 
    




