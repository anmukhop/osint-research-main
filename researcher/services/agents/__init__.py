"""
OSINT Browser Agents
This package contains browser-based agents for various OSINT platforms.
"""
from .whatsmyname import WhatsMyNameAgent, search_username

def get_agent(agent_name: str):
    if agent_name == "whatsmyname":
        return WhatsMyNameAgent
    return None

def get_available_agents():
    return ["whatsmyname"]

__all__ = [
    "WhatsMyNameAgent",
    "search_username",
    "get_agent",
    "get_available_agents",
]
