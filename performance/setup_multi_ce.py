#!/usr/bin/env python3
"""
批量复制和配置多个 CE 实例
用于 Phase 3 性能测试
"""
import os
import sys
import shutil
import configparser
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

class MultiCESetup:
    def __init__(self, base_dir=None, num_ces=1):
        if base_dir is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.base_dir = base_dir
        self.num_ces = num_ces
        
        # CE 基础目录
        self.ce_base = os.path.join(base_dir, "CE")
    
    def copy_and_config_ce(self, ce_id, party_id, rpe_address, rpe_port):
        """
        复制并配置 CE
        
        Args:
            ce_id: CE ID，例如 "ce-1"
            party_id: Party ID，例如 1
            rpe_address: RPE 地址
            rpe_port: RPE 端口
        """
        party_ce_dir = os.path.join(self.base_dir, f"CE_party{party_id}")
        
        if os.path.exists(party_ce_dir):
            logger.warning("CE Party %d already exists, skipping..." % party_id)
            return party_ce_dir
        
        logger.info("Copying CE for Party %d (CE: %s)..." % (party_id, ce_id))
        shutil.copytree(self.ce_base, party_ce_dir, ignore=shutil.ignore_patterns('*.pyc', '__pycache__', '*.log', 'logs', 'performance_data'))
        
        # 创建必要的目录
        os.makedirs(os.path.join(party_ce_dir, "logs"), exist_ok=True)
        os.makedirs(os.path.join(party_ce_dir, "performance_data"), exist_ok=True)
        
        # 修改 config.toml
        config_file = os.path.join(party_ce_dir, "config.toml")
        if os.path.exists(config_file):
            config = configparser.ConfigParser()
            config.read(config_file)
            if 'ce' in config:
                config['ce']['local_ce'] = f'"{ce_id}"'
                config['ce']['rpe_address'] = f'"{rpe_address}"'
                config['ce']['rpe_port'] = f'"{rpe_port}"'
                # 保持其他字段不变（collaborative_ce_address, collaborative_ce_port, ce_port）
                with open(config_file, 'w') as f:
                    config.write(f)
            logger.info("Updated config.toml for CE Party %d" % party_id)
        else:
            # 如果 config.toml 不存在，从模板创建
            template_file = os.path.join(party_ce_dir, "config.toml.template")
            if os.path.exists(template_file):
                shutil.copy(template_file, config_file)
                config = configparser.ConfigParser()
                config.read(config_file)
                if 'ce' in config:
                    config['ce']['local_ce'] = f'"{ce_id}"'
                    config['ce']['rpe_address'] = f'"{rpe_address}"'
                    config['ce']['rpe_port'] = f'"{rpe_port}"'
                    with open(config_file, 'w') as f:
                        config.write(f)
                logger.info("Created config.toml from template for CE Party %d" % party_id)
            else:
                logger.warning("config.toml and template not found for CE Party %d" % party_id)
        
        return party_ce_dir
    
    def setup_multiple_ces(self, rpe_address="127.0.0.1", rpe_port="4455"):
        """
        设置多个 CE
        
        Args:
            rpe_address: RPE 地址（所有 CE 连接到同一个 RPE）
            rpe_port: RPE 端口（所有 CE 连接到同一个 RPE）
        """
        ce_dirs = []
        
        for i in range(1, self.num_ces + 1):
            ce_id = f"ce-{i}"
            ce_dir = self.copy_and_config_ce(ce_id, i, rpe_address, rpe_port)
            ce_dirs.append(ce_dir)
        
        logger.info("=" * 60)
        logger.info("Multi-CE setup completed!")
        logger.info("CEs: %s" % ", ".join(ce_dirs))
        logger.info("All CEs configured to connect to RPE at %s:%s" % (rpe_address, rpe_port))
        logger.info("=" * 60)
        
        return ce_dirs


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="批量复制和配置多个 CE")
    parser.add_argument("--num-ces", type=int, default=1, help="CE 数量")
    parser.add_argument("--rpe-address", type=str, default="127.0.0.1", help="RPE 地址")
    parser.add_argument("--rpe-port", type=str, default="4455", help="RPE 端口")
    parser.add_argument("--base-dir", type=str, default=None, help="基础目录")
    
    args = parser.parse_args()
    
    setup = MultiCESetup(base_dir=args.base_dir, num_ces=args.num_ces)
    setup.setup_multiple_ces(
        rpe_address=args.rpe_address,
        rpe_port=args.rpe_port
    )


if __name__ == "__main__":
    main()