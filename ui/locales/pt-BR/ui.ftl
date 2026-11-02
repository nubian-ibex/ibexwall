app-name = IbexWall
app-tagline = Proteção do sistema
nav-label = Navegação principal
nav-overview = Visão geral
nav-plugins = Plugins
nav-posture = Segurança do sistema
nav-history = Histórico
nav-settings = Configurações
sidebar-status-active = Proteção ativa
skip-to-content = Pular para o conteúdo

overview-title = Visão geral
overview-last-check = Última verificação completa { $when }
overview-never-checked = Nenhuma verificação foi feita ainda
overview-check-now = Verificar agora
overview-checking = Verificando…
overview-status-protected = Seu computador está protegido
overview-status-attention = Seu computador pode estar mais protegido
overview-status-unknown = Vamos verificar seu computador
overview-badge-protected = Protegido
overview-badge-attention = Atenção
overview-badge-unknown = Não verificado
overview-summary =
    { $failed ->
        [0] Todas as { $assessed } verificações possíveis aqui estão em dia.
        [one] { $passed } de { $assessed } verificações estão em dia. Há 1 recomendação que deixa o sistema mais seguro.
       *[other] { $passed } de { $assessed } verificações estão em dia. Há { $failed } recomendações que deixam o sistema mais seguro.
    }
overview-summary-unknown = Faça uma verificação para ver o quanto este computador está protegido. Nada é alterado.
overview-view-recommendation = Ver recomendação
overview-view-all = Ver todas as proteções
overview-run-first = Fazer a primeira verificação
overview-protections = Proteções
overview-recommendation = Recomendação
overview-not-assessed =
    { $count ->
        [one] 1 verificação ainda não pode ser avaliada.
       *[other] { $count } verificações ainda não podem ser avaliadas.
    }

trust-no-change = Nada muda no sistema sem a sua aprovação
trust-undo = Toda alteração pode ser desfeita
trust-open = Código aberto e auditável
trust-local = Seus dados ficam neste computador

score-label = Pontuação { $score } de 100
score-none = Sem pontuação ainda
score-of = de 100

card-boot = Inicialização segura
card-disk = Disco criptografado
card-firewall = Firewall
card-confinement = Limites dos programas
card-accounts = Acesso de administrador
card-ports = Exposição na rede
card-updates = Atualizações e firmware
card-state-ok = Em dia
card-state-attention = Atenção
card-state-unknown = Não avaliado
card-detail-checks = { $count } verificações

outcome-pass = Em dia
outcome-fail = Atenção
outcome-not-applicable = Não se aplica aqui
outcome-not-assessed = Ainda não avaliado

severity-info = Informação
severity-low = Baixa
severity-medium = Média
severity-high = Alta
severity-critical = Crítica

state-loading = Carregando…
state-empty-title = Nada para mostrar ainda
state-empty-body = Faça uma verificação e os resultados aparecerão aqui.
state-error-title = Não foi possível falar com o serviço do IbexWall
state-error-body = O serviço de proteção não respondeu. Suas proteções continuam funcionando; esta janela só não consegue ler o estado delas.
state-denied-title = Permissão necessária
state-denied-body = Sua conta não tem permissão para ler esta informação. Peça a um administrador para liberar { $action }.
state-retry = Tentar de novo

theme-label = Tema
theme-system = Seguir o sistema
theme-light = Claro
theme-dark = Escuro
language-label = Idioma

plugins-title = Plugins
plugins-subtitle = Cada proteção é um plugin que você pode ligar ou desligar
plugins-kind-check = Somente leitura
plugins-kind-control = Altera o sistema
plugins-kind-monitor = Monitora
plugins-origin-official = Oficial
plugins-origin-community = Comunidade
plugins-origin-local = Local
plugins-enabled = Ligado
plugins-disabled = Desligado
plugins-detail = Detalhes
plugins-close = Fechar detalhes
plugins-permissions = O que este plugin pode fazer
plugins-permissions-write = Alterar arquivos em { $paths }
plugins-permissions-units = Controlar serviços: { $units }
plugins-permissions-sysctl = Definir parâmetros do kernel: { $keys }
plugins-permissions-exec = Executar programas: { $commands }
plugins-permissions-nft = Adicionar regras de firewall com prefixo próprio
plugins-permissions-none = Ler o sistema; ele não pode alterar nada
plugins-findings = Achados abertos
plugins-no-findings = Nenhum achado aberto
plugins-locked = Definido pela sua organização
plugins-incompatible = Incompatível com este sistema

simulate = Simular
apply = Aplicar alterações
applying = Aplicando…
confirm-title = Manter as alterações?
plan-expires = Esta prévia expira { $when }

may-affect-label = O que isto pode afetar
may-affect-title = Isto pode afetar
restore-point-note = Um ponto de restauração ({ $point }) é criado antes de qualquer alteração.

keep-changes-title = Manter as alterações
keep-changes-prompt = Manter as alterações? ({ $seconds } s restantes, depois disso elas são desfeitas automaticamente)
keep-changes = Manter alterações
undo-changes = Desfazer alterações

applied-committed = Alterações aplicadas
applied-rolled-back = Alterações desfeitas
simulate-empty = Nada a alterar

posture-title = Segurança do sistema
posture-subtitle = Cada verificação, o que significa e quanto vale
posture-how-title = Como calculamos
posture-how-intro = Cada verificação tem um peso por severidade. A pontuação é a soma dos pesos das verificações em dia, dividida pelos pesos das verificações que se aplicam a este computador.
posture-how-weight = Peso
posture-how-outcome = Situação
posture-how-na = Verificações que não se aplicam aqui e as que ainda não podem ser avaliadas não contam a favor nem contra.
posture-recommendation = Recomendação
posture-checks = Verificações
posture-open-findings = Achados abertos ({ $count })

history-title = Histórico
history-subtitle = Cada alteração, quem aprovou e o que aconteceu
history-actor-user = { $actor }
history-actor-system = O próprio IbexWall
history-result-committed = Aplicada e mantida
history-result-rolled_back = Desfeita
history-result-pending_confirm = Aguardando confirmação
history-result-failed = Falhou (desfeita)
history-empty-title = Nada foi alterado ainda
history-empty-body = Quando você aplicar uma proteção, ela aparece aqui com um jeito de desfazer.
history-undo = Desfazer esta alteração
history-view = Ver

settings-title = Configurações
settings-subtitle = Aparência e idioma
language-en = Inglês
language-pt-BR = Português (Brasil)

nav-dns = DNS seguro
dns-title = DNS seguro
dns-subtitle = Criptografe suas consultas DNS e bloqueie rastreadores e domínios maliciosos
dns-unavailable-title = O DNS seguro não está disponível
dns-unavailable-body = O plugin de DNS seguro não está instalado neste computador.
dns-status-off = O DNS seguro está desligado
dns-status-off-body = O computador envia as consultas DNS pelo servidor da própria rede.
dns-status-pass = Suas consultas DNS estão criptografadas
dns-status-pass-body = O resolvedor local está ativo e responde por este computador.
dns-status-fail = O DNS seguro está ligado, mas não funciona
dns-status-fail-body = O resolvedor local não está respondendo. Revise as opções abaixo ou desligue o recurso.
dns-status-not_applicable = O DNS seguro não se aplica aqui
dns-status-not_applicable-body = Este sistema não usa a configuração com que o DNS seguro funciona.
dns-status-not_assessed = Este sistema ainda não pode ser verificado
dns-status-not_assessed-body = Por enquanto o DNS seguro funciona com o systemd-resolved. Outras configurações ainda não são suportadas.
dns-status-unknown = Verificando
dns-status-unknown-body = O resultado aparece após a próxima verificação.
dns-provider = Provedor
dns-provider-quad9 = Quad9
dns-provider-quad9-logs = não registra o endereço IP dos usuários
dns-provider-cloudflare = Cloudflare
dns-provider-cloudflare-logs = trunca os endereços IP e os apaga em até 25 horas
dns-jurisdiction = Jurisdição: { $code }
dns-transport = Como as consultas são criptografadas
dns-transport-tls = DNS sobre TLS (recomendado)
dns-transport-https = DNS sobre HTTPS
dns-transport-h3 = DNS sobre HTTPS (HTTP/3)
dns-transport-quic = DNS sobre QUIC
dns-list = Lista de bloqueio
dns-list-none = Nenhuma
dns-list-hagezi-light = HaGeZi Light (menos bloqueios)
dns-list-hagezi-normal = HaGeZi Normal
dns-list-hagezi-pro = HaGeZi Pro (recomendada pelos autores)
dns-list-hagezi-pro-plus = HaGeZi Pro++ (mais bloqueios)
dns-list-hagezi-ultimate = HaGeZi Ultimate (pode quebrar sites)
dns-list-oisd-small = OISD small
dns-list-oisd-big = OISD big
dns-list-stevenblack = StevenBlack unified hosts
dns-enforcement = Recusar DNS sem criptografia
dns-enforcement-body = Nenhum programa consegue enviar consultas DNS em claro ou DoT por fora do DNS seguro.
dns-block-doh = Impedir que os navegadores contornem a proteção
dns-block-doh-body = Pede ao Firefox que mantenha o DNS próprio desligado. Nenhuma configuração do navegador muda sem a sua aprovação.
dns-review-note = Nada muda até você revisar as alterações exatas e aplicá-las.

change-failed-title = O IbexWall não pôde continuar
change-failed-other = A solicitação falhou. Nada foi alterado.
