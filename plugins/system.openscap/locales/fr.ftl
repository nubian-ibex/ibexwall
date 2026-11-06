openscap-failed-title = Une règle du profil de sécurité n'est pas respectée
openscap-failed-summary = La règle { $rule } du profil { $profile } n'est pas respectée sur cet ordinateur. Ouvrez la page de la règle dans le SCAP Security Guide pour savoir ce qu'elle demande et comment corriger.
openscap-may-affect-load = La vérification lit de nombreux fichiers et réglages et peut ralentir l'ordinateur pendant son exécution. Elle ne modifie rien.
detect-openscap-title = Vérification du profil de sécurité (OpenSCAP)
detect-openscap-none = OpenSCAP n'est pas installé. IbexWall n'installe rien ; pour l'obtenir, exécutez : { $install }
detect-openscap-no-content = OpenSCAP est installé mais le contenu SCAP Security Guide pour cette distribution ne l'est pas (par exemple le paquet scap-security-guide sur Fedora), donc il n'y a aucun profil de référence.
detect-openscap-ready = OpenSCAP et son contenu sont installés. Vous pouvez vérifier un profil maintenant ou selon un calendrier.
detect-openscap-scanned = La dernière vérification du profil { $profile } a validé { $passed } règles et en a échoué { $failed }. Les règles échouées sont listées ci-dessus, les plus graves d'abord.
