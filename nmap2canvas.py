#!/usr/bin/env python3
import xml.etree.ElementTree as ET
import json
import sys
import os
import uuid

def parse_nmap_xml(xml_file):
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except Exception as e:
        print(f"[-] Fehler beim Lesen der XML: {e}")
        sys.exit(1)
        
    host_data = {
        'ip': 'Unknown', 
        'os': [],
        'host_scripts': [],
        'ports': []
    }
    
    for host in root.findall('host'):
        status = host.find('status')
        if status is not None and status.attrib.get('state') == 'up':
            address = host.find('address')
            if address is not None:
                host_data['ip'] = address.attrib.get('addr')
            
            os_el = host.find('os')
            if os_el is not None:
                for osmatch in os_el.findall('osmatch'):
                    host_data['os'].append(f"{osmatch.attrib.get('name')} ({osmatch.attrib.get('accuracy')}%)")
            
            hostscript_el = host.find('hostscript')
            if hostscript_el is not None:
                for script in hostscript_el.findall('script'):
                    host_data['host_scripts'].append({
                        'id': script.attrib.get('id'),
                        'output': script.attrib.get('output', '').strip()
                    })

            ports = host.find('ports')
            if ports is not None:
                for port in ports.findall('port'):
                    state_el = port.find('state')
                    if state_el is not None and state_el.attrib.get('state') == 'open':
                        port_id = port.attrib.get('portid')
                        protocol = port.attrib.get('protocol')
                        reason = state_el.attrib.get('reason', '')
                        ttl = state_el.attrib.get('reason_ttl', '')
                        
                        service_el = port.find('service')
                        service_name = service_el.attrib.get('name', 'unknown') if service_el is not None else 'unknown'
                        product = service_el.attrib.get('product', '') if service_el is not None else ''
                        version = service_el.attrib.get('version', '') if service_el is not None else ''
                        
                        port_scripts = []
                        for script in port.findall('script'):
                            port_scripts.append({
                                'id': script.attrib.get('id'),
                                'output': script.attrib.get('output', '').strip()
                            })
                        
                        host_data['ports'].append({
                            'port': port_id,
                            'protocol': protocol,
                            'reason': reason,
                            'ttl': ttl,
                            'service': service_name,
                            'product': product,
                            'version': version,
                            'scripts': port_scripts
                        })
            break 
            
    return host_data

def calculate_node_height(text, width, chars_per_line_est=45, line_height=26, padding=50):
    """
    Berechnet dynamisch die Höhe der Box basierend auf dem Text, 
    Zeilenumbrüchen und geschätzten automatischen Word-Wraps.
    """
    lines = text.split('\n')
    total_visual_lines = 0
    for line in lines:
        # Berechnet, ob eine Zeile so lang ist, dass Obsidian sie umbricht
        wraps = max(1, len(line) // chars_per_line_est + 1)
        total_visual_lines += wraps
        
    calculated_height = (total_visual_lines * line_height) + padding
    return max(100, calculated_height) # Mindestens 100px hoch

def create_obsidian_canvas(data, output_file):
    nodes = []
    edges = []
    
    host_node_id = str(uuid.uuid4())
    current_y_right = 0  
    current_y_left = 0   
    
    # ---------------------------------------------------------
    # 1. PORTS UND SCRIPTS (Rechte Seite)
    # ---------------------------------------------------------
    for port in data['ports']:
        port_node_id = str(uuid.uuid4())
        
        # Text für Port-Box formatieren
        port_text = f"### Port {port['port']}/{port['protocol']}\n"
        port_text += f"**Service:** {port['service']}\n"
        if port['product'] or port['version']:
            port_text += f"**Version:** {port['product']} {port['version']}\n"
        if port['reason']:
            port_text += f"**State:** {port['reason']} (TTL: {port['ttl']})"
            
        port_text = port_text.strip()
        port_width = 320
        # HÖHE DYNAMISCH BERECHNEN:
        port_height = calculate_node_height(port_text, port_width, chars_per_line_est=40)
            
        nodes.append({
            "id": port_node_id,
            "type": "text",
            "text": port_text,
            "x": 300,
            "y": current_y_right,
            "width": port_width,
            "height": port_height,
            "color": "4" 
        })
        
        edges.append({
            "id": str(uuid.uuid4()),
            "fromNode": host_node_id,
            "fromSide": "right",
            "toNode": port_node_id,
            "toSide": "left"
        })
        
        # Child-Nodes für Nmap-Scripts dieses Ports
        script_y = current_y_right
        
        for script in port['scripts']:
            script_node_id = str(uuid.uuid4())
            script_text = f"**NSE: {script['id']}**\n```text\n{script['output']}\n```"
            
            script_width = 500
            # HÖHE DYNAMISCH BERECHNEN:
            script_height = calculate_node_height(script_text, script_width, chars_per_line_est=65)
            
            nodes.append({
                "id": script_node_id,
                "type": "text",
                "text": script_text,
                "x": 700,
                "y": script_y,
                "width": script_width,
                "height": script_height
            })
            
            edges.append({
                "id": str(uuid.uuid4()),
                "fromNode": port_node_id,
                "fromSide": "right",
                "toNode": script_node_id,
                "toSide": "left"
            })
            
            script_y += script_height + 30 # 30px Abstand zum nächsten Script
            
        # Nächste Port-Box muss unterhalb der Port-Box ODER der letzten Script-Box platziert werden
        block_height = max(port_height, script_y - current_y_right)
        current_y_right += block_height + 40 # 40px Abstand zum nächsten Port-Block
        
    # ---------------------------------------------------------
    # 2. HOST INFOS (Linke Seite)
    # ---------------------------------------------------------
    if data['os']:
        os_node_id = str(uuid.uuid4())
        os_text = "### OS Detection\n" + "\n".join([f"- {os}" for os in data['os'][:3]])
        
        os_width = 350
        os_height = calculate_node_height(os_text, os_width)
        
        nodes.append({
            "id": os_node_id,
            "type": "text",
            "text": os_text,
            "x": -500,
            "y": current_y_left,
            "width": os_width,
            "height": os_height,
            "color": "6" 
        })
        
        edges.append({
            "id": str(uuid.uuid4()),
            "fromNode": host_node_id,
            "fromSide": "left",
            "toNode": os_node_id,
            "toSide": "right"
        })
        current_y_left += os_height + 30
        
    for h_script in data['host_scripts']:
        h_script_node_id = str(uuid.uuid4())
        h_script_text = f"**Host-Script: {h_script['id']}**\n```text\n{h_script['output']}\n```"
        
        h_width = 400
        h_height = calculate_node_height(h_script_text, h_width, chars_per_line_est=50)
        
        nodes.append({
            "id": h_script_node_id,
            "type": "text",
            "text": h_script_text,
            "x": -500,
            "y": current_y_left,
            "width": h_width,
            "height": h_height,
            "color": "6"
        })
        
        edges.append({
            "id": str(uuid.uuid4()),
            "fromNode": host_node_id,
            "fromSide": "left",
            "toNode": h_script_node_id,
            "toSide": "right"
        })
        current_y_left += h_height + 30

    # ---------------------------------------------------------
    # 3. ZENTRALER HOST NODE
    # ---------------------------------------------------------
    # Wir platzieren den Host-Node vertikal zentriert zur rechten Seite
    host_y = (current_y_right - 100) // 2 if current_y_right > 0 else 0
    
    nodes.insert(0, {
        "id": host_node_id,
        "type": "text",
        "text": f"# Target\n**IP:** {data['ip']}",
        "x": -50,
        "y": host_y,
        "width": 200,
        "height": 100,
        "color": "1" 
    })
    
    # JSON speichern
    canvas = {
        "nodes": nodes,
        "edges": edges
    }
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(canvas, f, indent=4)
        
    print(f"[+] Canvas erfolgreich erstellt: {output_file}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: nmap2canvas <nmap_scan.xml> [output_name.canvas]")
        sys.exit(1)
        
    xml_input = sys.argv[1]
    
    if len(sys.argv) == 3:
        canvas_output = sys.argv[2]
    else:
        base_name = os.path.splitext(os.path.basename(xml_input))[0]
        canvas_output = f"{base_name}.canvas"
        
    if not canvas_output.endswith('.canvas'):
        canvas_output += '.canvas'
        
    print(f"[*] Verarbeite {xml_input}...")
    scan_data = parse_nmap_xml(xml_input)
    
    if not scan_data['ports']:
        print("[-] Keine offenen Ports im Scan gefunden oder XML fehlerhaft.")
    else:
        print(f"[*] {len(scan_data['ports'])} offene Ports gefunden.")
        create_obsidian_canvas(scan_data, canvas_output)
