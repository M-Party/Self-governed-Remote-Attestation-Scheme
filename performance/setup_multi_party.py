#!/usr/bin/env python3
"""
Copy and configure multiple participants, including Fabric Client, RPO, and RPE,
for Phase 2 multi-party tests.
"""
import os
import sys
import shutil
import json
import configparser
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

class MultiPartySetup:
    def __init__(
        self,
        base_dir=None,
        num_parties=3,
        transport="fabric",
        p2p_port=51051,
        p2p_host="127.0.0.1",
        ft_enabled=False,
        ft_base_port=56001,
        ft_host="127.0.0.1",
    ):
        if base_dir is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.base_dir = base_dir
        self.num_parties = num_parties
        self.transport = transport
        self.p2p_port = p2p_port
        self.p2p_host = p2p_host
        self.ft_enabled = ft_enabled
        self.ft_base_port = ft_base_port
        self.ft_host = ft_host
        
        # Base directories.
        self.fabric_client_base = os.path.join(base_dir, "fabric_service", "fabric_client")
        self.rpo_base = os.path.join(base_dir, "RPO")
        self.rpe_base = os.path.join(base_dir, "RPE")

    def _get_rpe_grpc_address(self, party_index, base_grpc_port, grpc_host):
        if self.transport == "p2p":
            return "%s:%d" % (self.p2p_host, self.p2p_port + party_index - 1)
        return "%s:%d" % (grpc_host, base_grpc_port + party_index - 1)

    def _get_p2p_peer_addresses(self, party_index):
        return [
            "%s:%d" % (self.p2p_host, self.p2p_port + peer_index - 1)
            for peer_index in range(1, self.num_parties + 1)
            if peer_index != party_index
        ]

    def _get_ft_peer_addresses(self):
        return ",".join(
            "rpe-%d=%s:%d" % (party_index, self.ft_host, self.ft_base_port + party_index - 1)
            for party_index in range(1, self.num_parties + 1)
        )
    

    def _recreate_party_dir(self, party_dir, source_dir, party_label, copy_kwargs=None):
        if os.path.exists(party_dir):
            logger.info("Removing existing %s at %s", party_label, party_dir)
            shutil.rmtree(party_dir)
        logger.info("Copying %s from %s", party_label, source_dir)
        if copy_kwargs:
            shutil.copytree(source_dir, party_dir, **copy_kwargs)
        else:
            shutil.copytree(source_dir, party_dir)

    def copy_and_config_fabric_client(self, party_id, grpc_port):
        """Copy and configure a Fabric Client instance."""
        party_fc_dir = os.path.join(self.base_dir, f"fabric_client_party{party_id}")
        
        self._recreate_party_dir(
            party_fc_dir,
            self.fabric_client_base,
            "Fabric Client Party %d" % party_id,
            copy_kwargs={"ignore": shutil.ignore_patterns('*.pyc', '__pycache__', '*.log')},
        )
        
        # Update the gRPC port when needed.
        config_file = os.path.join(party_fc_dir, "config", "config.toml")
        if os.path.exists(config_file):
            # Read and update the configuration.
            config = configparser.ConfigParser()
            config.read(config_file)
            if 'grpc' in config and 'port' in config['grpc']:
                config['grpc']['port'] = f'"{grpc_port}"'
                with open(config_file, 'w') as f:
                    config.write(f)

        # Prefer per-party credential store paths so concurrent fabric_clients
        # do not corrupt /tmp/hfc-kvs (Cannot deserialize the user).
        network_template = os.path.join(party_fc_dir, "config", "network.json.template")
        network_file = os.path.join(party_fc_dir, "config", "network.json")
        if os.path.exists(network_template):
            with open(network_template, "r") as f:
                network_content = f.read().replace("${PARTY_ID}", str(party_id))
            with open(network_file, "w") as f:
                f.write(network_content)
            # Ensure empty private stores for this party.
            os.makedirs("/tmp/hfc-kvs-%d" % party_id, exist_ok=True)
            os.makedirs("/tmp/hfc-cvs-%d" % party_id, exist_ok=True)
        
        return party_fc_dir
    
    def copy_and_config_rpo(self, party_id, rpe_id, rpo_port):
        """Copy and configure an RPO instance."""
        party_rpo_dir = os.path.join(self.base_dir, f"RPO_party{party_id}")
        
        self._recreate_party_dir(
            party_rpo_dir,
            self.rpo_base,
            "RPO Party %d (RPE: %s)" % (party_id, rpe_id),
        )
        
        # Update config.toml.
        config_file = os.path.join(party_rpo_dir, "config.toml")
        if os.path.exists(config_file):
            config = configparser.ConfigParser()
            config.read(config_file)
            if 'rpo' in config:
                config['rpo']['rpe_id'] = f'"{rpe_id}"'
                config['rpo']['port'] = f'"{rpo_port}"'
                config['rpo']['policies_path'] = '"policies-%d.json"' % self.num_parties
                with open(config_file, 'w') as f:
                    config.write(f)
        
        return party_rpo_dir

    def generate_policies_json(self, all_rpe_ids, all_rpe_configs, policies_template_path=None):
        """
        Generate policies.json containing all participating RPEs.
        
        Args:
            all_rpe_ids: List of all RPE IDs, for example ["rpe-1", "rpe-2", "rpe-3"]
            all_rpe_configs: Configuration for each RPE, for example:
                {
                    "rpe-1": {
                        "qeid_allowed": ["qeid-1"],
                        "tcb_allowed": ["tcb-1"],
                        "ca_signing_key_cert": "cert-1"
                    },
                    ...
                }
            policies_template_path: Optional policies.json template path
        """
        if policies_template_path is None:
            policies_template_path = os.path.join(self.rpo_base, "policies.json.template")
        
        # Read the template.
        with open(policies_template_path, 'r') as f:
            policies = json.load(f)
        
        # Generate configurations for all RPEs.
        rpe_list = []
        for rpe_id in all_rpe_ids:
            config = all_rpe_configs.get(rpe_id, {})
            rpe_config = {
                "id": rpe_id,
                "qeid_allowed": config.get("qeid_allowed", ["efbac5bb8d8cd796a8379405e5e846e2"]),
                "tcb_allowed": config.get("tcb_allowed", ["tcb-1"]),
                "ca_signing_key_cert": config.get("ca_signing_key_cert", f"S-Key-cert-{rpe_id}")
            }
            rpe_list.append(rpe_config)
        
        policies["rpe"] = rpe_list

        # Consensus-policy semantics: job is pure β; CE owns tcb_allowed.
        for job in policies.get("job") or []:
            if "tcb_allowed" in job:
                job.pop("tcb_allowed", None)
        for tcb in policies.get("tcb") or []:
            tcb.setdefault("min_status", "UpToDate")
            tcb.setdefault("fmspc", tcb.get("fmspc") or tcb.get("id"))
        for ce in policies.get("ce") or []:
            if not ce.get("tcb_allowed"):
                ce["tcb_allowed"] = ["tcb-1"]
        for conn in policies.get("connection") or []:
            # Prefer ce ids: if template still uses job-* refs, map via job table
            jobs = {j["id"]: j for j in (policies.get("job") or [])}
            server = conn.get("server")
            if server in jobs:
                conn["server"] = jobs[server]["ce"]
            clients = []
            for c in conn.get("clients") or []:
                clients.append(jobs[c]["ce"] if c in jobs else c)
            conn["clients"] = clients

        return policies

    def generate_policies_variants(self, all_rpe_ids, all_rpe_configs, policies_template_path=None):
        """
        Generate the data for policies-1.json through policies-N.json in one pass.

        Returns:
            {
                1: {...},
                2: {...},
                ...
                N: {...}
            }
        """
        policies_variants = {}
        for participant_count in range(1, len(all_rpe_ids) + 1):
            current_rpe_ids = all_rpe_ids[:participant_count]
            policies_variants[participant_count] = self.generate_policies_json(
                current_rpe_ids,
                all_rpe_configs,
                policies_template_path=policies_template_path,
            )
        return policies_variants

    def write_policies_variants(self, rpo_dir, policies_variants):
        """Write policies-1.json through policies-N.json to one RPO directory."""
        for participant_count, policies_json in policies_variants.items():
            policies_file = os.path.join(rpo_dir, "policies-%d.json" % participant_count)
            with open(policies_file, 'w') as f:
                json.dump(policies_json, f, indent=4)
            logger.info(
                "Generated policies-%d.json in %s with %d RPE(s)",
                participant_count,
                rpo_dir,
                participant_count,
            )
        full_policy = policies_variants[max(policies_variants.keys())]
        with open(os.path.join(rpo_dir, "policies.json"), 'w') as f:
            json.dump(full_policy, f, indent=4)
    
    def copy_and_config_rpe(self, party_id, rpe_id, rpe_port, rpo_address, rpo_port, grpc_address):
        """Copy and configure an RPE instance."""
        party_rpe_dir = os.path.join(self.base_dir, f"RPE_party{party_id}")
        
        self._recreate_party_dir(
            party_rpe_dir,
            self.rpe_base,
            "RPE Party %d (RPE: %s, Port: %s)" % (party_id, rpe_id, rpe_port),
        )
        
        # Update config.toml.
        config_file = os.path.join(party_rpe_dir, "config.toml")
        if os.path.exists(config_file):
            config = configparser.ConfigParser()
            config.read(config_file)
            if 'rpe' in config:
                config['rpe']['rpe_id'] = f'"{rpe_id}"'
                config['rpe']['rpe_port'] = f'"{rpe_port}"'
                config['rpe']['rpo_address'] = f'"{rpo_address}"'
                config['rpe']['rpo_port'] = f'"{rpo_port}"'
                config['rpe']['grpc_server_address'] = f'"{grpc_address}"'
                if self.transport == "p2p":
                    config['rpe']['grpc_peer_addresses'] = '"%s"' % ",".join(
                        self._get_p2p_peer_addresses(party_id)
                    )
                if "ft" not in config:
                    config["ft"] = {}
                config["ft"]["enabled"] = "true" if self.ft_enabled else "false"
                config["ft"]["quorum_mode"] = '"auto"'
                config["ft"]["quorum_override"] = "0"
                config["ft"]["listen_host"] = '"%s"' % self.ft_host
                config["ft"]["listen_port"] = '"%d"' % (self.ft_base_port + party_id - 1)
                config["ft"]["peer_addresses"] = '"%s"' % self._get_ft_peer_addresses()
                config["ft"]["echo_timeout_sec"] = "3"
                config["ft"]["recovery_timeout_sec"] = "8"
                config["ft"]["expt_cache_path"] = '"performance_data/expt_cache.json"'
                config["ft"]["counter_cache_path"] = '"performance_data/ft_counter_cache.json"'
                with open(config_file, 'w') as f:
                    config.write(f)
        
        # Create the performance_data directory.
        perf_dir = os.path.join(party_rpe_dir, "performance_data")
        os.makedirs(perf_dir, exist_ok=True)
        
        return party_rpe_dir
    
    def setup_multiple_parties(self, base_rpo_port=4433, base_rpe_port=4455, base_grpc_port=50051, 
                            rpo_host="127.0.0.1", grpc_host="127.0.0.1"):
        """
        Set up multiple participants.
        
        Args:
            base_rpo_port: Base RPO port, incremented per participant
            base_rpe_port: Base RPE port, incremented per participant
            base_grpc_port: Base gRPC port, incremented per participant
            rpo_host: RPO host address
            grpc_host: gRPC host address
        """
        party_dirs = {
            'fabric_clients': [],
            'rpos': [],
            'rpes': []
        }
        
        # Collect all RPE information for policies.json generation.
        all_rpe_ids = [f"rpe-{i}" for i in range(1, self.num_parties + 1)]
        all_rpe_configs = {}
        for rpe_id in all_rpe_ids:
            # Configure each RPE as needed for the deployment.
            # If all RPEs share the same configuration, it can be read from the template.
            all_rpe_configs[rpe_id] = {
                "qeid_allowed": ["feea1a922f97aee4d98e431a1068761a"],  # Update for the actual environment.
                "tcb_allowed": ["tcb-1"],  # Update for the actual environment.
                "ca_signing_key_cert": "-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE4k0UPMHPQ7GfD81M2Xu4TEQHQYKiJtE5\nSqhjpflPdn6kph9ZsbuUt6hEnMo/jJve7bPjsshp6G03Cu+ejGplRkcNrQEPJi2r\n7mzpBedryCClM5ALI0GAVvbwVI1p8BVA\n-----END PUBLIC KEY-----"  # Update for the actual environment.
            }
        
        # Generate policies-1.json through policies-N.json in one pass.
        policies_variants = self.generate_policies_variants(all_rpe_ids, all_rpe_configs)
        
        for i in range(1, self.num_parties + 1):
            rpe_id = f"rpe-{i}"
            rpo_port = base_rpo_port + i - 1
            rpe_port = base_rpe_port + i - 1
            grpc_port = base_grpc_port + i - 1
            
            # Fabric Client
            fc_dir = self.copy_and_config_fabric_client(i, grpc_port)
            party_dirs['fabric_clients'].append(fc_dir)
            
            # RPO
            rpo_dir = self.copy_and_config_rpo(i, rpe_id, rpo_port)
            self.write_policies_variants(rpo_dir, policies_variants)
            
            party_dirs['rpos'].append(rpo_dir)
            
            # RPE
            rpe_dir = self.copy_and_config_rpe(
                i, rpe_id, rpe_port, 
                rpo_host, rpo_port, 
                self._get_rpe_grpc_address(i, base_grpc_port, grpc_host)
            )
            party_dirs['rpes'].append(rpe_dir)
        
        logger.info("=" * 60)
        logger.info("Multi-party setup completed!")
        logger.info("Fabric Clients: %s" % ", ".join(party_dirs['fabric_clients']))
        logger.info("RPOs: %s" % ", ".join(party_dirs['rpos']))
        logger.info("RPEs: %s" % ", ".join(party_dirs['rpes']))
        logger.info("Each RPO now contains policies-1.json through policies-%d.json" % self.num_parties)
        logger.info("Transport mode for RPE grpc_server_address: %s" % self.transport)
        logger.info("=" * 60)
        
        return party_dirs

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Copy and configure multiple participants")
    parser.add_argument("--num-parties", type=int, default=3, help="Number of participants")
    parser.add_argument("--base-rpo-port", type=int, default=4433, help="Base RPO port")
    parser.add_argument("--base-rpe-port", type=int, default=4455, help="Base RPE port")
    parser.add_argument("--base-grpc-port", type=int, default=50051, help="Base gRPC port")
    parser.add_argument("--transport", type=str, choices=["fabric", "p2p"], default="fabric",
                        help="fabric: each RPE targets its own fabric_client port; p2p: each RPE targets its local P2P node")
    parser.add_argument("--p2p-port", type=int, default=51051,
                        help="Base P2P node port for transport=p2p; party i uses p2p-port+i-1")
    parser.add_argument("--p2p-host", type=str, default="127.0.0.1",
                        help="Host address used by P2P nodes for listening and peering when transport=p2p")
    parser.add_argument("--ft-enabled", action="store_true", help="Enable SRAS-FT in generated RPE configs")
    parser.add_argument("--ft-base-port", type=int, default=56001, help="Base SRAS-FT control port")
    parser.add_argument("--ft-host", type=str, default="127.0.0.1", help="SRAS-FT control host")
    
    args = parser.parse_args()
    
    setup = MultiPartySetup(
        num_parties=args.num_parties,
        transport=args.transport,
        p2p_port=args.p2p_port,
        p2p_host=args.p2p_host,
        ft_enabled=args.ft_enabled,
        ft_base_port=args.ft_base_port,
        ft_host=args.ft_host,
    )
    setup.setup_multiple_parties(
        base_rpo_port=args.base_rpo_port,
        base_rpe_port=args.base_rpe_port,
        base_grpc_port=args.base_grpc_port
    )

if __name__ == "__main__":
    main()
