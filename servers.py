import paramiko
from datetime import datetime
import os
import stat
import logging
import configparser
import time

# 配置日志，仅输出到控制台
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()  # 只输出到控制台
    ]
)
logger = logging.getLogger()

# 定义项目列表
projects = []

# 从配置文件读取项目信息
def load_projects_from_config(config_file='servers.cfg'):
    """从 .cfg 文件加载所有项目配置，支持带空格的路径和自定义端口"""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(script_dir, config_file)
    
    config = configparser.ConfigParser(interpolation=None)
    if not os.path.exists(config_path):
        logger.error(f"配置文件 {config_path} 不存在，无法继续执行")
        input("按 Enter 键退出程序...")
        exit(1)

    with open(config_path, 'r', encoding='utf-8') as f:
        config.read_file(f)
    
    for section in config.sections():
        try:
            ip = config[section].get('ip', '').strip('"')
            user = config[section].get('user', '').strip('"')
            password = config[section].get('password', '').strip('"')
            server_dir = config[section].get('server_dir', '').strip('"')
            pc_dir = config[section].get('pc_dir', '').strip('"')
            port = config[section].get('port', '22').strip('"')

            if not all([ip, user, password, server_dir, pc_dir]):
                raise KeyError("某些字段为空")

            try:
                port = int(port)
                if not (1 <= port <= 65535):
                    raise ValueError("端口号必须在 1-65535 之间")
            except ValueError as e:
                logger.error(f"配置文件 {section} 的端口号无效: {str(e)}，跳过此项")
                continue

            project = {
                'ip': ip,
                'user': user,
                'password': password,
                'server_dir': server_dir,
                'pc_dir': pc_dir,
                'port': port
            }
            projects.append(project)
            logger.info(f"加载配置: {section} (IP: {project['ip']}, Port: {project['port']}, server_dir: {project['server_dir']})")
        except KeyError as e:
            logger.error(f"配置文件 {section} 缺少必要字段或格式错误: {str(e)}，跳过此项")

# 定义递归传输函数，带重试机制
def sftp_get_recursive(sftp, remote_dir, local_dir, failed_files):
    """递归传输远程目录及其内容到本地，记录失败文件"""
    try:
        for entry in sftp.listdir_attr(remote_dir):
            remote_path = remote_dir + '/' + entry.filename
            local_path = os.path.join(local_dir, entry.filename)
            if stat.S_ISDIR(entry.st_mode):
                if not os.path.exists(local_path):
                    os.makedirs(local_path)
                sftp_get_recursive(sftp, remote_path, local_path, failed_files)
            else:
                max_retries = 3
                for attempt in range(max_retries):
                    try:
                        sftp.get(remote_path, local_path)
                        logger.info(f"成功传输文件: {remote_path} -> {local_path}")
                        break
                    except Exception as e:
                        if attempt < max_retries - 1:
                            logger.warning(f"传输 {remote_path} 失败 (尝试 {attempt + 1}/{max_retries}): {str(e)}，正在重试")
                            time.sleep(1)
                        else:
                            logger.error(f"传输 {remote_path} 最终失败: {str(e)}，跳过此文件")
                            failed_files.append(remote_path)
    except Exception as e:
        logger.error(f"遍历目录 {remote_dir} 时出错: {str(e)}，继续传输其他文件")

# 处理单个项目的传输
def transfer_project(project):
    """处理单个项目的文件传输并返回结果"""
    ip = project['ip']
    user = project['user']
    password = project['password']
    server_dir = project['server_dir']
    pc_base_dir = project['pc_dir']
    port = project['port']

    # 获取 server_dir 的最后一个目录名
    last_dir = os.path.basename(server_dir.rstrip('/'))
    now = datetime.now()
    current_date = f"{now.year}-{now.month}-{now.day}"
    local_dir = os.path.join(pc_base_dir, current_date)
    local_saved_dir = os.path.join(local_dir, last_dir)

    # 确保 pc_base_dir 存在
    try:
        if not os.path.exists(pc_base_dir):
            os.makedirs(pc_base_dir)
            logger.info(f"创建基础目录: {pc_base_dir}")
    except Exception as e:
        logger.error(f"创建基础目录 {pc_base_dir} 失败: {str(e)}，跳过此项目")
        return "完全失败", 0

    # 创建本地目录（包含日期和最后一个目录名）
    try:
        if not os.path.exists(local_saved_dir):
            os.makedirs(local_saved_dir)
        logger.info(f"创建本地目录: {local_saved_dir}")
    except Exception as e:
        logger.error(f"创建目录 {local_saved_dir} 失败: {str(e)}，跳过此项目")
        return "完全失败", 0

    # 建立 SSH 连接，指定端口
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(ip, username=user, password=password, port=port, timeout=10)
        logger.info(f"成功连接到服务器: {ip}:{port} (项目: {server_dir})")
    except Exception as e:
        logger.error(f"连接服务器 {ip}:{port} 失败: {str(e)}，跳过此项目")
        return "完全失败", 0

    # 打开 SFTP 会话并传输文件
    failed_files = []
    try:
        sftp = ssh.open_sftp()
        sftp_get_recursive(sftp, server_dir, local_saved_dir, failed_files)
        sftp.close()
    except Exception as e:
        logger.error(f"SFTP 操作 {server_dir} 出错: {str(e)}，跳过此项目")
        failed_files.append("SFTP 会话中断，未完成传输")
    finally:
        ssh.close()

    # 判断传输结果
    if not failed_files:
        logger.info(f"项目 {server_dir} 传输结果: 全部成功")
        return "全部成功", 0
    elif failed_files and failed_files[0] == "SFTP 会话中断，未完成传输":
        logger.info(f"项目 {server_dir} 传输结果: 完全失败")
        return "完全失败", len(failed_files)
    else:
        logger.info(f"项目 {server_dir} 传输结果: 部分失败，失败文件数量: {len(failed_files)}")
        return "部分失败", len(failed_files)

# 主函数，处理所有项目
def main():
    # 加载配置文件
    load_projects_from_config()
    if not projects:
        logger.error("没有可用的项目配置，无法继续执行")
        input("按 Enter 键退出程序...")
        exit(1)

    for project in projects:
        ip = project['ip']
        server_dir = project['server_dir']
        logger.info(f"开始处理项目: {ip} - {server_dir}")
        result, failed_count = transfer_project(project)
        if result == "部分失败":
            logger.info(f"项目 {ip} - {server_dir} 部分失败详情: 失败 {failed_count} 个文件")
        elif result == "完全失败":
            logger.info(f"项目 {ip} - {server_dir} 完全失败")

# 主程序入口
if __name__ == "__main__":
    main()
    input()