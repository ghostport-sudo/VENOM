import urllib.parse
from bs4 import BeautifulSoup
from typing import List, Dict, Any
from modules.base import BaseOSINTModule

class DuckDuckGoModule(BaseOSINTModule):
    """
    Autonomous Agent Web Search Module.
    Scrapes DuckDuckGo HTML results to provide live web context to the AI Analyst.
    """
    async def fetch(self, session) -> Any:
        query = f'"{self.target}"'
        url = f"https://html.duckduckgo.com/html/?q={urllib.parse.quote(query)}"
        
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }
        
        html = await self._request(session, "GET", url, headers=headers, timeout=15)
        
        if isinstance(html, dict) and "Status" in html:
            return [] # WAF or error
            
        results = []
        try:
            soup = BeautifulSoup(html, 'html.parser')
            for a in soup.find_all('a', class_='result__snippet'):
                snippet = a.text.strip()
                href = a.get('href', '')
                if snippet:
                    results.append({"snippet": snippet, "url": href})
                    if len(results) >= 5: 
                        break
        except Exception:
            pass
            
        return results

    def normalize(self, raw_data: Any) -> Dict[str, Any]:
        return {"results": raw_data}
