#!/usr/bin/env python3
"""
批量复制和配置多个参与方（Fabric Client、RPO、RPE）
用于 Phase 2 多方场景测试
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
    def __init__(self, base_dir=None, num_parties=3):
        if base_dir is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.base_dir = base_dir
        self.num_parties = num_parties
        
        # 基础目录
        self.fabric_client_base = os.path.join(base_dir, "fabric_service", "fabric_client")
        self.rpo_base = os.path.join(base_dir, "RPO")
        self.rpe_base = os.path.join(base_dir, "RPE")
    
    def copy_and_config_fabric_client(self, party_id, port_offset=0):
        """复制并配置 Fabric Client"""
        party_fc_dir = os.path.join(self.base_dir, f"fabric_client_party{party_id}")
        
        if os.path.exists(party_fc_dir):
            logger.warning("Fabric Client Party %d already exists, skipping..." % party_id)
            return party_fc_dir
        
        logger.info("Copying Fabric Client for Party %d..." % party_id)
        shutil.copytree(self.fabric_client_base, party_fc_dir, ignore=shutil.ignore_patterns('*.pyc', '__pycache__', '*.log'))
        
        # 修改 gRPC 端口（如果需要）
        config_file = os.path.join(party_fc_dir, "config", "config.toml")
        if os.path.exists(config_file):
            # 读取和修改配置
            config = configparser.ConfigParser()
            config.read(config_file)
            if 'grpc' in config and 'port' in config['grpc']:
                # 去除引号并转换为整数
                port_str = config['grpc']['port'].strip('"\'')  # 去除单引号和双引号
                base_port = int(port_str)
                config['grpc']['port'] = f'"{base_port + port_offset}"'  # 保持 TOML 格式的引号
                with open(config_file, 'w') as f:
                    config.write(f)
        
        return party_fc_dir
    
    def copy_and_config_rpo(self, party_id, rpe_id, rpo_port):
        """复制并配置 RPO"""
        party_rpo_dir = os.path.join(self.base_dir, f"RPO_party{party_id}")
        
        if os.path.exists(party_rpo_dir):
            logger.warning("RPO Party %d already exists, skipping..." % party_id)
            return party_rpo_dir
        
        logger.info("Copying RPO for Party %d (RPE: %s)..." % (party_id, rpe_id))
        shutil.copytree(self.rpo_base, party_rpo_dir)
        
        # 修改 config.toml
        config_file = os.path.join(party_rpo_dir, "config.toml")
        if os.path.exists(config_file):
            config = configparser.ConfigParser()
            config.read(config_file)
            if 'rpo' in config:
                config['rpo']['rpe_id'] = f'"{rpe_id}"'
                config['rpo']['port'] = f'"{rpo_port}"'
                with open(config_file, 'w') as f:
                    config.write(f)
        
        return party_rpo_dir

    def generate_policies_json(self, all_rpe_ids, all_rpe_configs, policies_template_path=None):
        """
        生成包含所有参与方 RPE 的 policies.json
        
        Args:
            all_rpe_ids: 所有 RPE ID 列表，例如 ["rpe-1", "rpe-2", "rpe-3"]
            all_rpe_configs: 每个 RPE 的配置信息，例如：
                {
                    "rpe-1": {
                        "qeid_allowed": ["qeid-1"],
                        "tcb_allowed": ["tcb-1"],
                        "ca_signing_key_cert": "cert-1"
                    },
                    ...
                }
            policies_template_path: policies.json 模板路径（可选）
        """
        if policies_template_path is None:
            policies_template_path = os.path.join(self.rpo_base, "policies.json.template")
        
        # 读取模板
        with open(policies_template_path, 'r') as f:
            policies = json.load(f)
        
        # 生成所有 RPE 的配置
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

        return policies
    
    def copy_and_config_rpe(self, party_id, rpe_id, rpe_port, rpo_address, rpo_port, grpc_address):
        """复制并配置 RPE"""
        party_rpe_dir = os.path.join(self.base_dir, f"RPE_party{party_id}")
        
        if os.path.exists(party_rpe_dir):
            logger.warning("RPE Party %d already exists, skipping..." % party_id)
            return party_rpe_dir
        
        logger.info("Copying RPE for Party %d (RPE: %s, Port: %s)..." % (party_id, rpe_id, rpe_port))
        shutil.copytree(self.rpe_base, party_rpe_dir)
        
        # 修改 config.toml
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
                with open(config_file, 'w') as f:
                    config.write(f)
        
        # 创建 performance_data 目录
        perf_dir = os.path.join(party_rpe_dir, "performance_data")
        os.makedirs(perf_dir, exist_ok=True)
        
        return party_rpe_dir
    
    def setup_multiple_parties(self, base_rpo_port=4433, base_rpe_port=4455, base_grpc_port=50051, 
                            rpo_host="127.0.0.1", grpc_host="127.0.0.1"):
        """
        设置多个参与方
        
        Args:
            base_rpo_port: RPO 基础端口（每个参与方递增）
            base_rpe_port: RPE 基础端口（每个参与方递增）
            base_grpc_port: gRPC 基础端口（每个参与方递增）
            rpo_host: RPO 主机地址
            grpc_host: gRPC 主机地址
        """
        party_dirs = {
            'fabric_clients': [],
            'rpos': [],
            'rpes': []
        }
        
        # 收集所有 RPE 信息（用于生成 policies.json）
        all_rpe_ids = [f"rpe-{i}" for i in range(1, self.num_parties + 1)]
        all_rpe_configs = {}
        for rpe_id in all_rpe_ids:
            # 这里可以根据实际情况配置每个 RPE 的信息
            # 如果所有 RPE 使用相同的配置，可以从模板读取
            all_rpe_configs[rpe_id] = {
                "qeid_allowed": ["feea1a922f97aee4d98e431a1068761a"],  # 根据实际情况修改
                "tcb_allowed": ["tcb-1"],  # 根据实际情况修改
                "ca_signing_key_cert": "-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE4k0UPMHPQ7GfD81M2Xu4TEQHQYKiJtE5\nSqhjpflPdn6kph9ZsbuUt6hEnMo/jJve7bPjsshp6G03Cu+ejGplRkcNrQEPJi2r\n7mzpBedryCClM5ALI0GAVvbwVI1p8BVA\n-----END PUBLIC KEY-----"  # 根据实际情况修改
            }
        
        # 生成统一的 policies.json（包含所有 RPE）
        policies_json = self.generate_policies_json(all_rpe_ids, all_rpe_configs)
        
        for i in range(1, self.num_parties + 1):
            rpe_id = f"rpe-{i}"
            rpo_port = base_rpo_port + i - 1
            rpe_port = base_rpe_port + i - 1
            grpc_port = base_grpc_port + i - 1
            
            # Fabric Client
            fc_dir = self.copy_and_config_fabric_client(i, port_offset=i-1)
            party_dirs['fabric_clients'].append(fc_dir)
            
            # RPO（需要为每个 RPO 复制 policies.json）
            rpo_dir = self.copy_and_config_rpo(i, rpe_id, rpo_port)
            
            # 复制统一的 policies.json 到每个 RPO 目录
            policies_file = os.path.join(rpo_dir, "policies.json")
            with open(policies_file, 'w') as f:
                json.dump(policies_json, f, indent=4)
            logger.info("Generated policies.json for RPO Party %d with all %d RPEs" % (i, self.num_parties))
            
            party_dirs['rpos'].append(rpo_dir)
            
            # RPE
            rpe_dir = self.copy_and_config_rpe(
                i, rpe_id, rpe_port, 
                rpo_host, rpo_port, 
                f"{grpc_host}:{grpc_port}"
            )
            party_dirs['rpes'].append(rpe_dir)
        
        logger.info("=" * 60)
        logger.info("Multi-party setup completed!")
        logger.info("Fabric Clients: %s" % ", ".join(party_dirs['fabric_clients']))
        logger.info("RPOs: %s" % ", ".join(party_dirs['rpos']))
        logger.info("RPEs: %s" % ", ".join(party_dirs['rpes']))
        logger.info("Each RPO's policies.json contains all %d RPEs" % self.num_parties)
        logger.info("=" * 60)
        
        return party_dirs

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="批量复制和配置多个参与方")
    parser.add_argument("--num-parties", type=int, default=3, help="参与方数量")
    parser.add_argument("--base-rpo-port", type=int, default=4433, help="RPO 基础端口")
    parser.add_argument("--base-rpe-port", type=int, default=4455, help="RPE 基础端口")
    parser.add_argument("--base-grpc-port", type=int, default=50051, help="gRPC 基础端口")
    
    args = parser.parse_args()
    
    setup = MultiPartySetup(num_parties=args.num_parties)
    setup.setup_multiple_parties(
        base_rpo_port=args.base_rpo_port,
        base_rpe_port=args.base_rpe_port,
        base_grpc_port=args.base_grpc_port
    )

if __name__ == "__main__":
    main()