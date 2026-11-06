openscap-failed-title = Uma regra do perfil de segurança falha
openscap-failed-summary = A regra { $rule } do perfil { $profile } não é cumprida neste computador. Abra a página da regra no SCAP Security Guide para ver o que ela pede e como corrigir.
openscap-may-affect-load = A verificação lê muitos arquivos e configurações e pode deixar o computador mais lento enquanto roda. Ela não altera nada.
detect-openscap-title = Verificação de perfil de segurança (OpenSCAP)
detect-openscap-none = O OpenSCAP não está instalado. O IbexWall não instala nada; para obtê-lo, execute: { $install }
detect-openscap-no-content = O OpenSCAP está instalado, mas o conteúdo do SCAP Security Guide desta distribuição não (por exemplo, o pacote scap-security-guide no Fedora), então não há perfil para conferir.
detect-openscap-ready = O OpenSCAP e o conteúdo dele estão instalados. Você pode conferir um perfil agora ou em horário marcado.
detect-openscap-scanned = A última verificação do perfil { $profile } passou em { $passed } regras e falhou em { $failed }. As regras que falharam estão listadas acima, das piores às melhores.
