"""
Docker client for container runtime analysis.

Uses docker-py library for:
- docker ps, docker inspect
- Container user, ports, resources
- Image analysis
"""


import docker
from typing import Optional
from docker.models.containers import Container


class DockerScanner:
    def __init__(self, docker_host: Optional[str] = None, verbose: bool = False):
        self.docker_host = docker_host
        self.verbose = verbose
        self.client = None
    
    def connect(self) -> docker.DockerClient:
        """Connect to Docker daemon and return client."""
        if self.verbose:
            print(f"[DEBUG] Docker: creating client (docker_host={self.docker_host!r})")
        
        try:
            self.client = docker.DockerClient(base_url=self.docker_host) if self.docker_host else docker.from_env()
            if self.verbose:
                info = self.client.version()
                print(f"[DEBUG] Docker: connected, server_version={info.get('Version')!r}")
            return self.client
        except Exception as exc:
            if self.verbose:
                print(f"[DEBUG] Docker: client creation failed: {exc!r}")
            raise RuntimeError(f"Docker daemon not accessible ({exc})")
    
    def get_target_container(self) -> Container:
        """Get first running container (same logic as before)."""
        if self.verbose:
            print("[DEBUG] Docker: listing running containers...")
        
        containers = self.client.containers.list(filters={"status": "running"})
        if not containers:
            if self.verbose:
                print("[DEBUG] Docker: no running containers found")
            raise RuntimeError("No running Docker containers found")
        
        container = containers[0]
        if self.verbose:
            print(f"[DEBUG] Docker: selected container name={container.name!r}, id={container.id[:12]!r}")
        return container
    
    def get_container_info(self, container: Container) -> dict:
        """Extract common container info used by checks."""
        return {
            "user": container.attrs.get("Config", {}).get("User", "") or "",
            "ports": container.attrs.get("HostConfig", {}).get("PortBindings", {}) or {},
            "memory_limit": container.attrs.get("HostConfig", {}).get("Memory"),
            "cpu_limit": container.attrs.get("HostConfig", {}).get("CpuQuota") or container.attrs.get("HostConfig", {}).get("NanoCpus"),
            "healthcheck": container.attrs.get("Config", {}).get("Healthcheck"),
            "image": container.image.tags[0] if container.image.tags else "unknown",
            "env": container.attrs.get("Config", {}).get("Env", []),
        }