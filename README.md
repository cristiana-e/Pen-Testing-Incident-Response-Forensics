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

  <img width="50%" alt="image" src="https://github.com/cristiana-e/Pen-Testing-Incident-Response-Forensics/assets/19941757/7d7bd8a2-4da2-4a41-b335-fa398f6a7817">

- Formas passivas: É possível monitorar funcionários para tentar obter alguma informação ou credencial. Utilizar de Listeners no tráfego de rede da empresa para pbservar como as comunicações são feitas.

- Formas ativas: É possível mapear a rede, portas abertas para tentar encontrar formas de entrar no sistema, ou até mesmo quebrar senhas.

- Engenharia social: As vezes é necessários tentar fazer com que essas informações te sejam entregues.

### Ferramentas de scan


<img width="50%" alt="image" src="https://github.com/cristiana-e/Pen-Testing-Incident-Response-Forensics/assets/19941757/68a080e4-c1cc-41db-af05-5a24f9689bc3">

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

<img width="50%" alt="image" src="https://github.com/cristiana-e/Pen-Testing-Incident-Response-Forensics/assets/19941757/9733d530-8cfc-4a89-b4c0-0e339e5f8d85">

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

<img width="30%" alt="image" src="https://github.com/cristiana-e/Pen-Testing-Incident-Response-Forensics/assets/19941757/8eab4869-a652-4ff4-a7eb-a75260f6ac5e">

- Background: fornecerá uma visão geral de todos os envolvidos, os objetivos do teste e outros detalhes que poderão fornecer contexto para o pentest.

- Postura Geral: é uma narrativa da efetividade do teste e da habilidade dos profissionais pen testers de alcançar os objetivos que foram definidos na fase de planejamento. Pode ser falado sobre as vulnerabilidades encontradas e se a equipe foi capaz de superá-las e atingir os objetivos.

- Ranking de Risco: são o resultado de várias pontuações ou metodoligias de ranqueamento que a equipe escolheu durante a fase de planejamento. O ranqueamento de risco vai de baixo a extremo e, baseado no que foi encontrado durante os testes, é possível informar onde eles estão na escala de risco.


- Achados Gerais: fornece um resumo dos riscos encontrados durante o teste e um formato estatístico ou gráfico básico. Além disso, a causa do problema deve ser apresentada em um formato de fácil leitura, como na figura abaixo em que o gráfico mostra a causa dos riscos que foram explorados.

<img width="50%" alt="image" src="https://github.com/cristiana-e/Pen-Testing-Incident-Response-Forensics/assets/19941757/42003e42-5282-4d1d-8655-f3f25926e264">

- Recomendações: são as recomendações para a empresa, deixando-os a par do que é necessário fazer para corrigir as vulnerabilidades exploradas.

- Roteiro: O roteiro irá quebrar as suas recomendações em um plano de ação de 30, 60 e 90 dias, com os riscos mais graves para serem corrigidos primeiro.

## Relatório Técnico

O relatório técnico pode ser quebrado em seis ou sete categorias diferentes.

<img width="70%" alt="image" src="https://github.com/cristiana-e/Pen-Testing-Incident-Response-Forensics/assets/19941757/d725be0b-d487-47f5-b1ac-2bb095b08b44">

- Introdução: irá trazer muitas coisas já mencionadas no backgroud do sumário executivo mas, ao invés de resumir essas informações, o relatório técnico erá detalhar o nome de cada uma das pessoas envolvidas, informações de contatos, os exatos objetivos do teste, o que está dentro e fora do escopo, as abordagens. Tudo é detalhadamente informado.

- Escopo: é onde será informado como foram adquiridas todas as informações durante a fase de descoberta, foram coletadas de forma ativa ou passiva, quais informações foram adquiridas da corporação ou do pessoal.

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

# Resposta a Incidentes

<img width="70%" alt="image" src="https://github.com/cristiana-e/Pen-Testing-Incident-Response-Forensics/assets/19941757/36ca2db5-1314-4b7d-a857-c201fef57181">


Serão abordados o conceito de resposta a incidentes e suas fases essenciais: 

- preparação
- detecção e análise
- contenção, erradicação e recuperação
- atividades pós-incidente.

## Eventos e Incidentes

A distinção entre evento e incidente é crucial: 
um evento é uma ação comum, como digitar ou receber um email, que pode escalar para um incidente se resultar em múltiplas ocorrências suspeitas em curto período. Os sistemas de detecção de intrusão identificam esses eventos, e a equipe de resposta a incidentes valida esses alertas, caracterizando-os como incidentes quando representam ameaças aos sistemas de TI e impactam negativamente os negócios.

## Por que resposta a incidentes é importante?

A resposta a incidentes é uma ação rápida necessária para detectar incidentes, minimizar perdas e destruição, mitigar as fraquezas exploradas e restaurar os serviços de TI. Ela é importante por oferecer uma abordagem sistemática para lidar com incidentes, minimizar perdas de informação, interrupções de serviço e custos, além de fornecer informações valiosas para prevenir incidentes futuro.

## Equipes de Respostas a Incidentes

Existem diferentes tipos de equipes de resposta a incidentes, que podem ser centralizadas, distribuídas geograficamente ou coordenadoras, sem autoridade direta, mas que fornecem orientação a outras equipes. Essas equipes devem manter uma relação de trabalho com diversas áreas da organização, incluindo gestão, segurança da informação, suporte de TI, departamento jurídico, relações públicas, recursos humanos, planejamento de continuidade dos negócios e gestão de segurança física e instalações.

<img width="60%" alt="image" src="https://github.com/cristiana-e/Pen-Testing-Incident-Response-Forensics/assets/19941757/3bf638b3-6cd8-4cbc-8bbc-236ed88258f2">

## Vetores de Ataque

As organizações devem estar preparadas para responder a vetores de ataque comuns, como mídia removível não autorizada, ataques de força bruta, ameaças via web e email, ataques de personificação e perda ou roubo de equipamento físico. Em caso de incidente, é essencial documentar e ser capaz de responder a perguntas sobre o ataque, como a sua natureza, o porquê, quando e como aconteceu, o impacto e as medidas tomadas para prevenir futuros incidentes.

<img width="30%" alt="image" src="https://github.com/cristiana-e/Pen-Testing-Incident-Response-Forensics/assets/19941757/3f8122b5-d95e-4a0b-ab07-745e61fe3217">

## Perguntas de base

<img width="50%" alt="image" src="https://github.com/cristiana-e/Pen-Testing-Incident-Response-Forensics/assets/19941757/eb50e7bf-c393-48a9-bfc4-65d3b34e9f76">

## Frameworks

Este conteúdo é baseado no framework de resposta a incidente do National Institute of Standards and Technology (NIST), mas o Sans Institute também fornece uma estrutura não muito diferente do NIST. Conheça a diferença entre eles [aqui](https://cybersecurity.att.com/blogs/security-essentials/incident-response-steps-comparison-guide).

![image](https://github.com/cristiana-e/Pen-Testing-Incident-Response-Forensics/assets/19941757/551acc8a-b6aa-4e5e-92f9-a0508d82b2bf)

# Fase de Preparação

## Políticas de REsposta a Incidentes
- Definição de Papéis: Importante para determinar o escopo de suporte para cada membro da equipe.
- Ferramentas e Recursos: Para identificação e recuperação de dados comprometidos.
- Testes de Política: Essenciais devido à evolução contínua das ameaças de cibersegurança.
- Plano de Ação Detalhado: Para executar a resposta do início ao fim.

## Recursos 

<img width="50%" alt="image" src="https://github.com/cristiana-e/Pen-Testing-Incident-Response-Forensics/assets/19941757/5731f617-033b-4f09-b67a-bfbe32169007">


### Comunicações e Instalações para o Manejo de Incidentes

"Tempo é um dos fatores mais importantes em resposta a incidentes".

- Informações de contato e cadeia de comando.
- Mecanismos de relatório de incidentes (software, bancos de dados, sistemas de ticket).
- Smartphones e software de criptografia para equipe.
- “Sala de guerra” centralizada e armazenamento seguro para ativos recuperados.

### Hardware/Software

- Estações de trabalho forenses digitais e dispositivos de backup.
- Laptops de reserva, servidores, equipamentos de rede e equivalentes em máquinas virtuais.
- Mídia removível, impressoras portáteis, sniffers de pacotes e analisadores de protocolo.
- Acessórios para coleta de evidências.

### Análise de Incidentes

- Lista completa de portas e documentação apropriada.
- Diagrama de rede dos ativos críticos.
- Baselines de rede e organização para comparação.
- Hashes criptográficos.

## Prevenção de Incidentes

"Manter o número de incidentes rasoavelmente baixo é muito importante para a proteção dos processos de negócios da organização. Se os controles de segurança são insuficientes, maiores volumes de incidentes podem ocorrer, sobrecarregando o time de resposta a incidentes."

Embora fora do escopo principal da equipe de resposta a incidentes, a prevenção é fundamental para reduzir a carga de trabalho. Aconselhar sobre:

- Avaliações de Risco: Periódicas para sistemas e aplicações.
- Segurança de Hosts e Redes: Configurações padrão, ACLs estritas e monitoramento contínuo.
- Perímetro de Rede: Configuração para negar atividades não expressamente permitidas.
- Prevenção de Malware: Software distribuído por toda a organização.
- Conscientização e Treinamento dos Usuários: Políticas e procedimentos atualizados.

<img width="40%" alt="image" src="https://github.com/cristiana-e/Pen-Testing-Incident-Response-Forensics/assets/19941757/e53d6494-1ae9-4deb-96ae-43217575fbc3">

## Lista de Preparação (SANS Institute)

- Todos os membros estão cientes das políticas de segurança da empresa?
- Todos os membros da equipe de resposta a incidentes sabem quem contatar?
- Todos os respondedores de incidentes têm acesso a ferramentas e toolkits para resposta a incidentes?
- Todos os membros participaram de simulações para praticar e melhorar a proficiência regularmente?

## Precursores e Indicadores

Basicamente precursores são sinais de que um incidente pode ocorrer no futuro e indicadores são sinais de que um incidente já ocorreu ou está acorrendo.

<img width="70%" alt="image" src="https://github.com/cristiana-e/Pen-Testing-Incident-Response-Forensics/assets/19941757/0906c8aa-81e2-4a87-80f8-62999ce8bc97">

## Sistemas de Monitoramento

- IDS (Intrusion Detection Systems): Sistemas de monitoramento que coletam informações.
- IPS (Intrusion Prevention Systems): Sistemas de controle que filtram pacotes que não cumprem políticas de segurança.
- DLP (Data Loss Prevention): Ferramentas e processos para evitar perda, mau uso ou acesso não autorizado a dados sensíveis.
- SIEM (Security Information and Event Management): Solução que combina a gestão de eventos de segurança com a gestão de informações de segurança, fornecendo uma visão holística dos logs para criação de eventos ou alertas.

## Documentação

A documentação é um dos aspectos mais importantes da resposta a incidentes e deve acontecer do início ao fim. Reserve algum tempo para ler [este artigo](https://sansorg.egnyte.com/dl/Hr5l5oGAJZ) para esclarecer como a documentação afeta a resposta a incidentes. 

<img width="70%" alt="image" src="https://github.com/cristiana-e/Pen-Testing-Incident-Response-Forensics/assets/19941757/301f878e-a598-4636-8e85-8fe13cae781e">

## Priorização de Impactos (segundo o National Institute of Security and Technology)

### Impactos Funcionais

- Nenhum: Sem efeito nos serviços da organização.
- Baixo: Perda mínima de eficiência, mas serviços críticos mantidos para alguns usuários.
- Médio: Perda de serviço para um subconjunto de usuários.
- Alto: Incapacidade total de fornecer serviços.

<img width="70%" alt="image" src="https://github.com/cristiana-e/Pen-Testing-Incident-Response-Forensics/assets/19941757/0de6a365-e44a-498d-b221-d5d3203dafae">


### Impactos na Informação

- Nenhum: Nenhuma informação comprometida.
- Violação de Privacidade: Informações pessoais sensíveis acessadas ou exfiltradas.
- Violação Proprietária: Informações proprietárias não classificadas acessadas ou infiltradas.
- Perda de Integridade: Informações sensíveis ou privadas alteradas ou deletadas.

<img width="70%" alt="image" src="https://github.com/cristiana-e/Pen-Testing-Incident-Response-Forensics/assets/19941757/17c59638-c61d-4edd-a924-74182801cd2c">

### Capacidade de Recuperação

- Regular: Previsível com recursos existentes.
- Suplementada: Previsível, mas necessita de assistência externa.
- Estendida: Incerta quanto ao tempo de recuperação, requer ajuda externa.
- Irrecuperável: Recuperação não é possível, como dados sensíveis divulgados publicamente.

<img width="70%" alt="image" src="https://github.com/cristiana-e/Pen-Testing-Incident-Response-Forensics/assets/19941757/8aee7ad4-018e-4ceb-90e1-ac8c0daa80ee">

## Comunicação Pós-Detecção

Deve-se notificar todas as partes relevantes ou potencialmente envolvidas, incluindo o diretor de informações (CIO), chefia de segurança da informação, equipes de resposta a incidentes internas e externas, proprietário do sistema, recursos humanos, relações públicas, departamento jurídico e autoridades policiais (se necessário).

# Contenção, Erradicação e Recuperação

## Escolhendo Estratégias de Contenção

"Contenção é importante antes que um incidente sobrecarregue recursos ou aumente os danos. Estratégias de contenções variam baseadas no tipo de incidente. Por exemplo, a estratégia para conter uma infecção de malware nascida de um e-mail é diferente da estratégia de um ataque DDoS."

- Considerações da NIST: Avaliar dano potencial, necessidade de preservar evidências, disponibilidade do serviço afetado, tempo e recursos para implementação, eficácia e duração da solução.

<img width="30%" alt="image" src="https://github.com/cristiana-e/Pen-Testing-Incident-Response-Forensics/assets/19941757/1da02234-40bb-466c-a079-47ef94991bf8">

### Forense na Resposta a Incidentes

Processo forense:
- Backup de Imagem do Sistema: Criar antes de qualquer alteração para evitar adulteração dos dados.
- Coleta de Evidências: Utilizar a imagem para investigação.
- Cadeia de Custódia: Documentar meticulosamente o manuseio da evidência.

## Erradicação e Recuperação

- Eradicação: Eliminação de componentes do incidente, como contas de usuários e vulnerabilidades exploradas. Inclui desativação de serviços e contas e remoção de tudo que foi tocado pela ameaça.
- Recuperação: Inclui a restauração de sistemas a partir de backups limpos, reconstrução de sistemas, substituição de arquivos comprometidos, instalação de patches, alteração de senhas e ajuste do perímetro de rede.
- Monitoramento Pós-Reparo: Alto nível de teste e monitoramento para garantir que os sistemas restaurados não estejam mais comprometidos, podendo levar semanas ou meses e feito em fases para monitoramento próximo.

<img width="60%" alt="image" src="https://github.com/cristiana-e/Pen-Testing-Incident-Response-Forensics/assets/19941757/5c781756-0592-4834-844c-5f6b5a9394b8">

## Lista de Verificação do SANS Institute para Contenção, Erradicação e Recuperação

### Contenção

- É possível isolar o problema?
- Todos os sistemas afetados estão isolados dos não afetados?
- Foram criadas cópias forenses dos sistemas afetados para análise?


### Erradicação

- É viável reimagem do sistema?
- Foram aplicados patches e contra-medidas?
- Todo o malware e outros artefatos deixados foram removidos?


### Recuperação

- Quais ferramentas serão usadas para testar, monitorar e garantir que os sistemas restaurados não sejam comprometidos novamente pelos mesmos métodos do incidente original?

# Automação

Um dos principais desafios enfrentados por todos os campos da segurança cibernética é o aumento esmagador de ameaças sem um aumento proporcional de profissionais de segurança cibernética para lidar com elas. Todos os sinais apontam para a automação como um elemento central para ajudar a mitigar as tarefas repetitivas e aumentar o tempo de resposta a eventos e ameaças. Leia [este artigo](https://www.sans.org/white-papers/38862/) sobre automação na resposta a incidentes.

## Atividades Pós-Incidente

"Realizar uma reunião de 'missão aprendida' com todas as partes envolvidas após um grande incidente, e opcionalmente periódicamente após menores incidentes de acordo com o que os recursos permitirem, podem ser de extrema ajuda em melhorar as medidas de seguranças e o processo de tratamento de incidentes." - NIST.SP.800-61

### Missão Aprendida

- O que exatamente aconteceu e em quais momentos?
- Como o desempenho do pessoal e da gestão foi na resolução do incidente?
- Os procedimentos documentados foram seguidos e são adequados?
- Que informações seriam úteis ter mais cedo?
- Quais ações tomadas inibiram a recuperação?
- Como o compartilhamento de informações com outras organizações poderia melhorar?
- Que ações corretivas podem prevenir incidentes semelhantes no futuro?
- Quais precursores ou indicadores poderiam ser monitorados para detectar eventos similares?

*Incluir descobertas na documentação existente para melhor preparação em incidentes futuros.

### Outras Atividades Pós-Incidente

- Utilização dos Dados Coletados: Analisar os tempos de resposta, dados impactados, duração da resolução e recuperação para melhorar as métricas da organização.
- Retenção de Evidências: Armazenamento e arquivamento de informações coletadas para uso em processos legais, garantindo a preservação da cadeia de custódia.
- Revisão de Documentação: Reavaliar toda a documentação relacionada à resposta a incidentes para identificar e corrigir lacunas.

<img width="740" alt="image" src="https://github.com/cristiana-e/Pen-Testing-Incident-Response-Forensics/assets/19941757/053e96a9-e1a9-4af4-af13-b1e8728cc7ad">

## Estudo de Caso

 [Este caso](https://www.sans.org/reading-room/whitepapers/incident/practical-incident-response-network-based-attack-37920) de estudo de uma resposta a incidente de uma amecaça baseada em rede. 

 # Acompanhando um Profissional

Neste estudo de caso de resposta a incidentes, Tommy Patton, um profissional com 5 anos de experiência em cibersegurança, mostra seu processo de resposta a incidentes utilizando a ferramenta IBM QRadar. 

## Etapa 1: Preparação

- Identificação de ameaças comuns como ataques de software, extração de dados, sabotagem da informação e roubo de equipamentos.
- Reconhecimento de vetores de ataque possíveis.
- Preparação envolve coletar informações essenciais, como:
    -    Listagem de Ativos: Priorização por importância e risco.
    -    Lista de Stakeholders: Contatos cruciais para notificar durante um incidente.
    -    Definição de Gatilhos de Investigação: Estabelecimento de eventos que iniciam a resposta.

## Etapa 2: Detecção e Análise

- Alertas são recebidos e o processo de detecção e análise é iniciado.
- Análise Detalhada: Investigação da natureza do alerta, determinando o ponto de entrada, a amplitude e a validade.

Questões a Responder:
    -  Ação autorizada por um administrador?
    -  Ataque usando conta de administrador de dispositivo remoto?
    -  Quantos dispositivos estão afetados?

Documentação e Escalada: Notificação das partes envolvidas e registro detalhado do incidente.

### Ferramentas Utilizadas:

- IBM QRadar (SIEM): Coleta, processa e armazena dados de eventos de sistemas, executando análise baseada em regras.
- McAfee ePolicy Orchestrator (HBSS): Previne, detecta e remove malware em sistemas Windows.
- Next Generation Firewalls: Oferecem inspeção de estado, correspondência de assinaturas e inspeção de carga de pacotes para filtragem.

## Etapa 3: Contenção, Erradicação e Recuperação

Contenção: Impedir mais danos isolando o sistema afetado.
Erradicação: Remover a ameaça do sistema.
Recuperação: Restaurar os sistemas afetados para retomar as operações normais de negócios.

## Etapa 4: Atividades Pós-Incidente

Análise de Ação Após Incidente: Revisão crítica das ações tomadas para aprender com as deficiências.
Relatórios Pós-Ação: Documentação para tornar a resposta a incidentes mais eficiente.

## Dentro do Qradar

### Seleção de Estratégia de Contenção com IBM QRadar

Referências de Incidentes: Criadas quando uma regra é ativada e a ação para criar uma ofensa é definida.
Interface do QRadar: Listagem das ofensas detectadas pelo motor de regras.
Priorização: Determinada pela magnitude.

## Examinando uma Ofensa de Magnitude 5

- Página de Resumo: Fornece detalhes como IPs de origem, IPs de destino, fontes de logs envolvidas e categorias dos eventos.
- Análises Importantes: Anotações principais e detecção de URL maliciosa baseada na comparação de consultas DNS com um conjunto de referência que contém URLs maliciosas.

## Processo de Resposta a Incidentes Iniciado

- Confirmação de Atividade Maliciosa: A consulta DNS maliciosa foi resolvida para um IP que não é da rede privada, indicando que o endereço DNS foi resolvido com sucesso.
- Documentação Detalhada do Incidente: Preenchimento de um formulário de resposta a incidentes, incluindo tipo de incidente, fonte de detecção, ambiente afetado, IPs envolvidos e ações tomadas.

## Resposta e Recuperação

- Desconexão da Rede: Submissão de um ticket para desativar o ponto de conexão da estação de trabalho.
- Varredura com Antivírus: Após a desativação, iniciar a varredura para detectar outros possíveis malwares.
- Recriação: Mesmo com varredura limpa, a máquina deve ser recriada por ter alcançado a rede de controle de botnet.

## Fechamento do Incidente

- Registro de Ações: Após as etapas de resposta, toda a informação é processada e arquivada para referência futura.
- Encerramento no QRadar: A ofensa é fechada no sistema e deixa de aparecer nas ofensas ativas.

## Avaliação de Outras Ofensas

- Possível Ataque DDoS: Verificação de eventos e, no caso de ser atividade típica do usuário, identificar como falso positivo.
- Ajustes na Regra do QRadar: Se necessário, alterar a regra para reduzir os falsos positivos futuros e documentar as mudanças.

## Análise de Ofensa com Alta Severidade

Primeira Observação: Nome do evento indica arquivo infectado sem opção de limpeza e acesso negado pelo sistema operacional.
Na Página de Resumo: Há detalhes sobre a infecção do arquivo e a inexistência de um limpador.
Análise dos Eventos: Detecta-se que a infecção está em um arquivo na lixeira do sistema.

## Processo de Resposta a Incidentes

Documentação do Incidente: Registro do tempo e anotação detalhada da ocorrência.
Contato com a Equipe de Rede: Solicitação para desabilitar a conexão da estação de trabalho afetada.
Comunicação com Partes Interessadas: Conforme listado na etapa de preparação.
Execução de Varredura Antivírus (AV): Aguardando resultados para ação subsequente.
Adição de novas anotações e detalhes durante o processo.

## Resultados da Varredura AV

Persistência do Arquivo Infectado: O arquivo ainda está presente, mesmo após a varredura, indicando a necessidade de reimagem do sistema.
Avaliação e Recomendação: Encaminhamento do caso para reimagem após consulta ao gestor de acessos (IAM).

## Elaboração do Relatório de Ação Pós-Incidente

Registro de Eficiências e Erros: Documentação contínua de falhas e sucessos para melhorar a resposta a incidentes.

## Melhoria da Eficiência

Revisão da Eficiência: Identificação de oportunidades de aprimoramento, como verificar a eficácia das ações antes de investigações mais profundas.
Comunicação com Acionistas: Reconhecimento da necessidade de notificação precoce durante o processo.


## Revisão do Processo de Resposta a Incidentes

Preparação: Identificação de ativos, eventos e contatos.
Detecção e Análise: Pesquisa de eventos e determinação do escopo do incidente.
Contenção, Erradicação e Recuperação: Desconexão de sistemas afetados, busca por ameaças adicionais e restauração do estado funcional.
Atividade Pós-Incidente: Relatório de ação pós-incidente para otimização contínua da resposta a incidentes.

Ambos os incidentes analisados necessitaram que os sistemas fossem recriados, conforme a avaliação.

# Ferramentas na REsposta a Incidente

Leia [este artigo](https://www.cynet.com/blog/the-7-best-free-and-open-source-incident-response-tools/) para ver quais outras ferramentas estão sendo usadas para resposta a incidentes.
  
