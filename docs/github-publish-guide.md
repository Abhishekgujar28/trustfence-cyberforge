# Publish the TrustFence starter project to GitHub

The project folder is intentionally ready to publish as a new repository. The connected GitHub actions available in this workspace do not include creating a repository, so create it in GitHub first.

1. Open https://github.com/new while signed in to your account.
2. Repository name suggestion: `trustfence-cyberforge`.
3. Choose Public if you want judges to access the repo; do not add a README, license, or `.gitignore` on GitHub because they are already included here.
4. Unzip the source bundle and open a terminal in the extracted `trustfence_project` directory.
5. Run:

```bash
git init
git add .
git commit -m "Initial TrustFence CyberForge MVP"
git branch -M main
git remote add origin https://github.com/Abhishekgujar28/trustfence-cyberforge.git
git push -u origin main
```

If you choose a different repo name or GitHub owner, replace the remote URL with the URL GitHub shows you.

Never commit API keys, `.env` files, access tokens, private data, or real emails. This starter uses synthetic scenarios only. For a judge-ready repo, include an actual deployed demo link only after you have tested it and confirmed the link is public.
