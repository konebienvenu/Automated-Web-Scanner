# 🎓 Bootcamp Oral Defense Cheat Sheet (Fiche de Soutenance)

> Ce document a été spécialement conçu pour vous préparer à présenter et soutenir ce projet de fin de bootcamp devant un jury d'examinateurs, un tuteur ou un recruteur en cybersécurité.

---

## 1. Le Pitch du Projet (Présentation en 2-3 minutes)

**"Bonjour à tous,**

Dans le cadre de la validation de mes acquis en cybersécurité, j'ai conçu et développé un **scanner d'audit web automatisé** axé sur deux vecteurs critiques d'hygiène et de conformité web :
1. **L'analyse approfondie des en-têtes de sécurité HTTP (Secure Headers)** selon les recommandations OWASP.
2. **La détection active des failles de configuration CORS (Cross-Origin Resource Sharing)** selon la spécification RFC 6454.

Trop souvent, les scanners se contentent de lire passivement des en-têtes sans tester le comportement réel de l'application. Mon outil implémente un moteur de **sondage actif (active probing)** qui soumet différentes origines malveillantes (domaines arbitraires, origine `null`, contournements par sous-domaines mal ancrés) et vérifie si le serveur autorise de manière illégitime la fuite de données d'utilisateurs authentifiés (`Access-Control-Allow-Credentials: true`).

Le scanner génère un scoring de risque de 0 à 100, attribue une note de sécurité (de A+ à F), et produit des rapports exécutifs au format **HTML moderne**, **JSON exploitable en CI/CD**, et **Markdown**. Enfin, j'ai intégré un **serveur de démonstration vulnérable/durci** permettant de valider l'ensemble des scénarios d'attaque hors-ligne."

---

## 2. Déroulement de la Démonstration en Direct (Live Demo Script)

Pour votre démo, ouvrez **deux terminaux** :

### Étape 1 : Démarrer le serveur de test (Terminal 1)
```bash
python main.py demo-server --port 8888
```
*Commentaire à dire au jury :*  
*"Pour cette démo, je lance le serveur de test embarqué qui simule différents environnements vulnérables et durcis."*

### Étape 2 : Scanner l'endpoint vulnérable aux failles CORS critiques (Terminal 2)
```bash
python main.py scan http://127.0.0.1:8888/vulnerable/cors-reflected-creds --html rapport_vuln.html
```
*Montrez au jury :*
- La détection de la faille **CRITIQUE** : Réflexion de l'origine de l'attaquant avec `Access-Control-Allow-Credentials: true`.
- L'absence des en-têtes défensifs (CSP, HSTS, X-Frame-Options).
- La note finale : **Note F** (Score 0/100).
- Ouvrez le fichier `rapport_vuln.html` dans votre navigateur pour montrer le tableau de bord exécutif.

### Étape 3 : Scanner l'endpoint sécurisé et durci
```bash
python main.py scan http://127.0.0.1:8888/secure/hardened
```
*Montrez au jury :*
- Tous les en-têtes OWASP sont conformes (HSTS preload, CSP strict, X-Content-Type-Options: nosniff, etc.).
- Les requêtes CORS d'attaquants sont rejetées.
- La note finale : **Note A+** (Score 100/100).

### Étape 4 : Montrer la suite de tests unitaires
```bash
python -m pytest tests/
```
*Commentaire à dire au jury :*  
*"Le projet intègre une suite de tests unitaires avec pytest couvrant 100% des règles d'audit, validée par un workflow GitHub Actions pour l'intégration continue."*

---

## 3. Questions Fréquentes du Jury & Réponses Types

### Q1 : "Pourquoi avoir choisi de faire un scan CORS actif plutôt que passif ?"
> **Réponse attendue :**  
> *"Une analyse passive ne lit que la réponse statique sans savoir comment le serveur réagit à des origines spécifiques. Or, les failles CORS les plus dangereuses surviennent lorsque le serveur dynamique lit l'en-tête `Origin` de la requête HTTP et la reflète dynamiquement dans `Access-Control-Allow-Origin`. Sans envoyer de probe active avec une origine tierce (comme `https://evil-attacker.com` ou `Origin: null`), il est impossible de détecter cette vulnérabilité critique."*

### Q2 : "Pourquoi la combinaison `Access-Control-Allow-Origin: *` avec des cookies est-elle impossible dans les navigateurs modernes ?"
> **Réponse attendue :**  
> *"La spécification W3C/Fetch interdit strictement l'utilisation conjointe du wildcard `*` et de `Access-Control-Allow-Credentials: true`. Les navigateurs bloquent la lecture de la réponse si cette combinaison est reçue. Cependant, pour contourner cette restriction, de nombreux développeurs font l'erreur d'implémenter un mécanisme qui reflète l'origine reçue, ce qui réintroduit exactement le même risque critique de vol de session."*

### Q3 : "En quoi `Content-Security-Policy: frame-ancestors` est-il supérieur à `X-Frame-Options` ?"
> **Réponse attendue :**  
> *"`X-Frame-Options` (RFC 7034) est un ancien en-tête limité aux valeurs `DENY` ou `SAMEORIGIN` (la directive `ALLOW-FROM` étant obsolète et mal supportée). CSP `frame-ancestors` (niveau 2 et 3) permet de définir précisément une liste blanche de domaines autorisés à intégrer la page dans une iframe, tout en supportant les sous-domaines et les schémas HTTPS de manière granulaire."*

### Q4 : "Quel est le risque de l'origine `null` dans CORS ?"
> **Réponse attendue :**  
> *"L'en-tête `Origin: null` est émis par le navigateur dans des contextes particuliers, notamment depuis une iframe isolée par sandbox (`<iframe sandbox='allow-scripts'>`), ou depuis un schéma `data:`. Si un serveur fait confiance à `null`, un attaquant hébergeant n'importe quel site web peut simplement encapsuler son script malveillant dans une iframe sandboxée pour usurper cette origine et dérober des données sensibles."*

### Q5 : "Comment ce scanner s'intègre-t-il dans un pipeline CI/CD DevSecOps ?"
> **Réponse attendue :**  
> *"J'ai conçu l'option `--fail-on <SEVERITY>` (par exemple `--fail-on HIGH`) et la sortie JSON. Dans un pipeline GitLab CI ou GitHub Actions, la commande analyse l'environnement de staging. Si une vulnérabilité critique ou élevée est détectée, le script retourne un code d'erreur 1 qui bloque automatiquement le déploiement en production tant que la régression n'a pas été corrigée."*
