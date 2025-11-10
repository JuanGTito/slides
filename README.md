## Network Scanner (Ping + ARP)

Script de línea de comandos en Python para listar dispositivos en una red local.

### Requisitos
- Linux con utilidades `ip` y `ping` disponibles en el PATH.
- Python 3.8+.

No requiere instalar paquetes externos.

### Instalación
No se necesita instalación. Puede ejecutarse directamente:

```bash
python3 network_scanner.py --help
```

### Uso básico

Escaneo automático (detecta la red del interfaz por defecto):

```bash
python3 network_scanner.py
```

Especificar la red a escanear (CIDR):

```bash
python3 network_scanner.py --cidr 192.168.1.0/24
```

Incluir dispositivos vistos en la tabla ARP aunque no respondan al ping:

```bash
python3 network_scanner.py --include-arp
```

Desactivar resolución inversa DNS para mayor velocidad:

```bash
python3 network_scanner.py --no-dns
```

Elegir formato de salida:

```bash
python3 network_scanner.py --format json
python3 network_scanner.py --format csv
```

Controlar concurrencia y timeout del ping:

```bash
python3 network_scanner.py --workers 256 --timeout 1.0
```

### Salida ejemplo (tabla)

```
IP Address       MAC Address         Hostname
---------------  ------------------  ---------------------
192.168.1.1      aa:bb:cc:dd:ee:ff   router.localdomain
192.168.1.42     11:22:33:44:55:66   host.local
```

### Notas
- El escaneo por ping puede no detectar dispositivos que bloqueen ICMP.
- `--include-arp` puede ayudar a descubrir más dispositivos si hubo tráfico reciente en la red.
- La detección automática de red usa `ip route` y `ip addr` para identificar el interfaz por defecto y su prefijo.
