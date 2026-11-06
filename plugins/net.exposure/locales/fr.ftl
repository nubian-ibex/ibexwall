exposure-open-title = Un port répond sur cet ordinateur
exposure-open-summary = Le port TCP { $port } ({ $service }) répond sur { $addresses }. Vérifiez que c'est voulu ; tout ce que vous n'utilisez pas est mieux fermé.
exposure-may-affect-logs = L'analyse ouvre une connexion vers chaque port des adresses de cet ordinateur, donc les services qui journalisent les connexions les listeront.
detect-exposure-title = Ports ouverts, vus depuis cet ordinateur
detect-exposure-none = nmap n'est pas installé. IbexWall n'installe rien ; pour l'obtenir, exécutez : { $install }
detect-exposure-ready = nmap est installé. Une analyse ne couvre que les adresses de cet ordinateur, jamais une autre machine.
detect-exposure-scanned = Une analyse a eu lieu ; les ports qui répondent sont listés ci-dessus. Vue depuis la machine elle-même, elle ne montre pas ce qu'un pare-feu bloque depuis l'extérieur.
