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
 
# Ataque

Enquanto a análise de vulnerabilidades confere a possível existência de uma vulnerabilidade, a fase de ataque explora essas vulnerabilidades para confirmar sua existência.

## Fases do ataque

<img width="1079" alt="image" src="https://github.com/cristiana-e/Pen-Testing-Incident-Response-Forensics/assets/19941757/9733d530-8cfc-4a89-b4c0-0e339e5f8d85">

### Categorias de vulnerabilidades que podem ser exploradas nos ataques

- Configurações incorretas: são geralmente configurações default que são inseguras.

- Falhas de kernel (kernel flaws): Por ser o núcleo de um SO, qualquer falha no kernel pode colocar todo o sistema de segurança em risco.

- Validações de input insuficientes: Aplicações que não validam devidamente os inputs de usuários podem sofrer com ataques como injeção SQL.

- Link simbólico (symlink): é um arquivo que aponta para outro arquivo. OS incluem programas que podem mudar a permissão de um arquivo. Se esse programa for executado com privilégios, um usuário poderia usar symlinks para enganar esses programas para modificar os listar arquivos críticos do sistema.

-  Ataque descritor de Arquivos: descritor de arquivos são numeros utilizados pelo sistema para rastrear os arquivos. Um ataque descritor de arquivos tem como objetivo sobrecarregar o sistema com muitos arquivos sendo abertos, de forma que operações legítimas são impedidas de serem executadas.

-  Race conditions: condições de corrida podem ocorrer quando um programa com acesso privilegiado é executado.  O atacante pode programar o ataque para se aproveitar desse acesso enquanto o programa é executado.

-  Buffer Overflow: ocorrem quando programas não conferem o tamanho apropriado dos inputs. Quando isso ocorre, código malicioso pode ser introduzido no sistema e executado junto ao programa ativo.

-  Permissões incorretas de arquivos e diretórios: essas permissões podem levar leitura ou escritas de arquivos de senhas ou adições na lista de hosts confiáveis.

### Arquivos para acesso
  [PTES-exploit](http://www.pentest-standard.org/index.php/Exploitation)
  [owasp-pentest](https://owasp.org/www-project-web-security-testing-guide/assets/archive/OWASP_Web_Application_Penetration_Checklist_v1_1.pdf)
  
# Reporting

Vamos quebrar a etapa de report em duas grandes categorias:

- Sumário Executivo
- Relatório Técnico

## Sumário Executivo

Esta etapa comunica para o leitor os objetivos específicos do teste de penetração e os achados de grande valor do exercício de teste.
É onde serão explicados Quem, O Quê, Quando e Onde enquanto no relatório técnico cobrirá o Por quê e Como.

O sumário executivo está quebrado em seis categorias:

<img width="615" alt="image" src="https://github.com/cristiana-e/Pen-Testing-Incident-Response-Forensics/assets/19941757/8eab4869-a652-4ff4-a7eb-a75260f6ac5e">

- Background: fornecerá uma visão geral de todos os envolvidos, os objetivos do teste e outros detalhes que poderão fornecer contexto para o pentest.

- Postura Geral: é uma narrativa da efetividade do teste e da habilidade dos profissionais pen testers de alcançar os objetivos que foram definidos na fase de planejamento. Pode ser falado sobre as vulnerabilidades encontradas e se a equipe foi capaz de superá-las e atingir os objetivos.

- Ranking de Risco: são o resultado de várias pontuações ou metodoligias de ranqueamento que a equipe escolheu durante a fase de planejamento. O ranqueamento de risco vai de baixo a extremo e, baseado no que foi encontrado durante os testes, é possível informar onde eles estão na escala de risco.


- Achados Gerais: fornece um resumo dos riscos encontrados durante o teste e um formato estatístico ou gráfico básico. Além disso, a causa do problema deve ser apresentada em um formato de fácil leitura, como na figura abaixo em que o gráfico mostra a causa dos riscos que foram explorados.

<img width="783" alt="image" src="https://github.com/cristiana-e/Pen-Testing-Incident-Response-Forensics/assets/19941757/42003e42-5282-4d1d-8655-f3f25926e264">

- Recomendações: são as recomendações para a empresa, deixando-os a par do que é necessário fazer para corrigir as vulnerabilidades exploradas.

- Roteiro: O roteiro irá quebrar as suas recomendações em um plano de ação de 30, 60 e 90 dias, com os riscos mais graves para serem corrigidos primeiro.

## Relatório Técnico

O relatório técnico pode ser quebrado em seis ou sete categorias diferentes.

<img width="1510" alt="image" src="https://github.com/cristiana-e/Pen-Testing-Incident-Response-Forensics/assets/19941757/d725be0b-d487-47f5-b1ac-2bb095b08b44">

- Introdução: irá trazer muitas coisas já mencionadas no backgroud do sumário executivo mas, ao invés de resumir essas informações, o relatório técnico erá detalhar o nome de cada uma das pessoas envolvidas, informações de contatos, os exatos objetivos do teste, o que está dentro e fora do escopo, as abordagens. Tudo é detalhadamente informado.

- Escopo: é onde será informado como foram adquiridas todas as informações durante a fase de coleta, foram coletadas de forma ativa ou passiva, quais informações foram adquiridas da corporação ou do pessoal.

- Avaliação de Vulnerabilidades: é detalhado exatamente quais ferramentas foram usadas e o que foi encontrado.

- Confirmação de vunerabilidades: quais vulnerabilidades encontradas que foram testadas para confirmar se elas são, ou não, um risco para a empresa, e o que foi feito para nesses testes.

- Pós Exploração: É a parte mais importante do relatório técnico. É a parte em que é abordado o caminho tomado para a escalada de privilégios e quais informações críticas foram encontradas a partir disso. Tudo de forma muito bem detalhada.

- Risco/Exposição: faz uma avaliação dos riscos e dos impactos causados/que podem ser causados.

[Como escrever um relatório de Pentest](https://sansorg.egnyte.com/dl/yNfjHOQix8)

## Ferramentas

Algumas ferramentas que valem a pena das uma pesquisada sobre.

- [nmap](https://nmap.org/book/man.html#man-description): é um scanner de rede open source que é utilizado para descobrir hosts e serviços.
- [JTRipper](https://www.openwall.com/john/): é uma ferramenta open source de auditoria de segurança e recuperação de senha.
- [Metasploit](https://docs.rapid7.com/metasploit/metasploit-basics/): é uma ferramenta exploração e validação de vulnerabilidade.
- [Wireshark](https://www.wireshark.org/#learnWS): analisador de protocolos de redes.

