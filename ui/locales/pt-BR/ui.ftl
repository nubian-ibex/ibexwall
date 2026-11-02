app-name = IbexWall
app-tagline = Proteção do sistema
nav-label = Navegação principal
nav-overview = Visão geral
nav-plugins = Plugins
nav-posture = Postura do sistema
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
