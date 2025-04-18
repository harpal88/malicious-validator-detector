from solana.rpc.api import Client

solana_client = Client("https://api.mainnet-beta.solana.com")

def check_validator(pubkey: str):
    """Basic validator check using Solana RPC"""
    vote_accounts = solana_client.get_vote_accounts(vote_pubkey=pubkey)
    if not vote_accounts.get('result'):
        return {"error": "Validator not found"}
    
    return {
        "pubkey": pubkey,
        "commission": vote_accounts['result']['current'][0]['commission'],
        "epoch_credits": vote_accounts['result']['current'][0]['epochCredits']
    }