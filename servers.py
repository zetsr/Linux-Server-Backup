import paramiko
from datetime import datetime
import os
import stat
import logging
import configparser
import time
import random
import string
import shutil
import tarfile
import posixpath
import traceback
from pathlib import Path

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
            linux_cache_dir = config[section].get('linux_cache_dir', '/tmp').strip('"')
            windows_cache_dir = config[section].get('windows_cache_dir', 'C:\\Temp').strip('"')
            max_retries = config[section].get('max_retries', '3').strip('"')

            if not all([ip, user, password, server_dir, pc_dir]):
                raise KeyError("某些字段为空")

            try:
                port = int(port)
                if not (1 <= port <= 65535):
                    raise ValueError("端口号必须在 1-65535 之间")
            except ValueError as e:
                logger.error(f"配置文件 {section} 的端口号无效: {str(e)}，跳过此项")
                continue

            try:
                max_retries = int(max_retries)
                if max_retries < 1:
                    max_retries = 3
            except:
                max_retries = 3

            project = {
                'ip': ip,
                'user': user,
                'password': password,
                'server_dir': server_dir,
                'pc_dir': pc_dir,
                'port': port,
                'linux_cache_dir': linux_cache_dir,
                'windows_cache_dir': windows_cache_dir,
                'max_retries': max_retries
            }
            projects.append(project)
            logger.info(f"加载配置: {section} (IP: {project['ip']}, Port: {project['port']}, server_dir: {project['server_dir']}, max_retries: {project['max_retries']})")
        except KeyError as e:
            logger.error(f"配置文件 {section} 缺少必要字段或格式错误: {str(e)}，跳过此项")

def generate_random_string(length=8):
    """生成随机字符串"""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def create_ssh_client(ip, user, password, port, timeout=30):
    """创建SSH客户端连接"""
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(ip, username=user, password=password, port=port, timeout=timeout)
    return ssh

def execute_remote_command(ssh, command):
    """执行远程命令并返回输出和状态"""
    stdin, stdout, stderr = ssh.exec_command(command)
    exit_status = stdout.channel.recv_exit_status()
    output = stdout.read().decode('utf-8').strip()
    error = stderr.read().decode('utf-8').strip()
    return exit_status, output, error

def compress_remote_directory(ssh, server_dir, linux_cache_dir):
    """在Linux服务器上压缩目录"""
    try:
        # 获取目录名
        dir_name = posixpath.basename(server_dir.rstrip('/'))
        
        # 生成唯一的压缩文件名
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        random_str = generate_random_string(6)
        tar_filename = f"{dir_name}_{timestamp}_{random_str}.tar.gz"
        tar_path = posixpath.join(linux_cache_dir, tar_filename)
        
        # 创建父目录
        parent_dir = posixpath.dirname(server_dir)
        
        # 构建压缩命令
        compress_cmd = f"cd '{parent_dir}' && tar -czf '{tar_path}' '{dir_name}'"
        
        logger.info(f"开始压缩远程目录: {server_dir} -> {tar_path}")
        
        # 执行压缩命令
        exit_status, output, error = execute_remote_command(ssh, compress_cmd)
        
        if exit_status != 0:
            logger.error(f"压缩失败: exit_status={exit_status}, error={error}")
            return None, None
        
        # 检查压缩文件是否存在
        check_cmd = f"ls -la '{tar_path}' 2>/dev/null || echo 'NOT_FOUND'"
        exit_status, output, error = execute_remote_command(ssh, check_cmd)
        
        if 'NOT_FOUND' in output:
            logger.error(f"压缩文件未创建成功: {tar_path}")
            return None, None
            
        logger.info(f"压缩成功: {tar_path}")
        return tar_path, tar_filename
        
    except Exception as e:
        logger.error(f"压缩过程中发生错误: {str(e)}")
        logger.error(traceback.format_exc())
        return None, None

def download_compressed_file(sftp, remote_tar_path, windows_cache_dir, tar_filename):
    """下载压缩文件到Windows缓存目录"""
    try:
        # 确保Windows缓存目录存在
        os.makedirs(windows_cache_dir, exist_ok=True)
        
        # 本地缓存路径
        local_tar_path = os.path.join(windows_cache_dir, tar_filename)
        
        logger.info(f"开始下载压缩文件: {remote_tar_path} -> {local_tar_path}")
        
        # 下载文件
        sftp.get(remote_tar_path, local_tar_path)
        
        # 验证文件是否下载成功
        if os.path.exists(local_tar_path) and os.path.getsize(local_tar_path) > 0:
            logger.info(f"下载成功: {local_tar_path}")
            return local_tar_path
        else:
            logger.error(f"下载失败或文件大小为0: {local_tar_path}")
            return None
            
    except Exception as e:
        logger.error(f"下载过程中发生错误: {str(e)}")
        logger.error(traceback.format_exc())
        return None

def extract_tar_file(local_tar_path, windows_cache_dir):
    """在Windows缓存目录解压文件"""
    try:
        # 生成解压目录名
        tar_name = os.path.basename(local_tar_path)
        extract_dir_name = os.path.splitext(os.path.splitext(tar_name)[0])[0]
        extract_path = os.path.join(windows_cache_dir, extract_dir_name)
        
        logger.info(f"开始解压文件: {local_tar_path} -> {extract_path}")
        
        # 如果解压目录已存在，先删除
        if os.path.exists(extract_path):
            shutil.rmtree(extract_path)
        
        # 创建解压目录
        os.makedirs(extract_path, exist_ok=True)
        
        # 解压文件
        with tarfile.open(local_tar_path, 'r:gz') as tar:
            tar.extractall(path=extract_path)
        
        # 验证解压是否成功
        if os.path.exists(extract_path) and len(os.listdir(extract_path)) > 0:
            logger.info(f"解压成功: {extract_path}")
            return extract_path
        else:
            logger.error(f"解压失败或目录为空: {extract_path}")
            return None
            
    except Exception as e:
        logger.error(f"解压过程中发生错误: {str(e)}")
        logger.error(traceback.format_exc())
        return None

def create_date_format_folder(pc_dir):
    """创建日期格式文件夹"""
    try:
        now = datetime.now()
        current_date = f"{now.year}-{now.month}-{now.day}"
        date_dir = os.path.join(pc_dir, current_date)
        
        logger.info(f"创建日期格式文件夹: {date_dir}")
        
        # 确保目录存在
        os.makedirs(date_dir, exist_ok=True)
        
        return date_dir
        
    except Exception as e:
        logger.error(f"创建日期格式文件夹失败: {str(e)}")
        logger.error(traceback.format_exc())
        return None

def atomic_move_directory(source_dir, target_parent_dir, last_dir_name):
    """原子移动目录到目标位置"""
    try:
        # 目标路径
        target_dir = os.path.join(target_parent_dir, last_dir_name)
        
        logger.info(f"原子移动目录: {source_dir} -> {target_dir}")
        
        # 如果目标已存在，先重命名为备份
        backup_dir = None
        if os.path.exists(target_dir):
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            random_str = generate_random_string(4)
            backup_dir = f"{target_dir}_backup_{timestamp}_{random_str}"
            logger.info(f"目标目录已存在，重命名为备份: {backup_dir}")
            os.rename(target_dir, backup_dir)
        
        # 执行原子移动
        shutil.move(source_dir, target_dir)
        
        # 验证移动是否成功
        if os.path.exists(target_dir) and not os.path.exists(source_dir):
            logger.info(f"原子移动成功: {target_dir}")
            
            # 成功后删除备份
            if backup_dir and os.path.exists(backup_dir):
                shutil.rmtree(backup_dir)
                logger.info(f"删除备份目录: {backup_dir}")
            
            return True
        else:
            logger.error(f"原子移动失败: 源目录仍存在或目标目录不存在")
            
            # 移动失败，恢复备份
            if backup_dir and os.path.exists(backup_dir):
                os.rename(backup_dir, target_dir)
                logger.info(f"恢复备份目录: {target_dir}")
            
            return False
            
    except Exception as e:
        logger.error(f"原子移动过程中发生错误: {str(e)}")
        logger.error(traceback.format_exc())
        return False

def cleanup_remote_files(ssh, remote_tar_path):
    """清理远程临时文件"""
    try:
        if ssh and remote_tar_path:
            # 检查文件是否存在
            check_cmd = f"ls '{remote_tar_path}' 2>/dev/null && echo 'EXISTS' || echo 'NOT_EXISTS'"
            exit_status, output, error = execute_remote_command(ssh, check_cmd)
            
            if 'EXISTS' in output:
                # 删除文件
                delete_cmd = f"rm -f '{remote_tar_path}'"
                exit_status, output, error = execute_remote_command(ssh, delete_cmd)
                
                if exit_status == 0:
                    logger.info(f"清理远程文件成功: {remote_tar_path}")
                else:
                    logger.warning(f"清理远程文件失败: {remote_tar_path}")
    except Exception as e:
        logger.warning(f"清理远程文件时发生错误: {str(e)}")

def cleanup_local_files(local_tar_path, extract_path):
    """清理本地临时文件"""
    try:
        # 删除压缩文件
        if local_tar_path and os.path.exists(local_tar_path):
            os.remove(local_tar_path)
            logger.info(f"清理本地压缩文件: {local_tar_path}")
        
        # 删除解压目录
        if extract_path and os.path.exists(extract_path):
            shutil.rmtree(extract_path)
            logger.info(f"清理本地解压目录: {extract_path}")
    except Exception as e:
        logger.warning(f"清理本地文件时发生错误: {str(e)}")

def atomic_transfer_project(project):
    """原子操作：压缩->复制->传输->解压->原子移动"""
    ip = project['ip']
    user = project['user']
    password = project['password']
    server_dir = project['server_dir']
    pc_base_dir = project['pc_dir']
    port = project['port']
    linux_cache_dir = project['linux_cache_dir']
    windows_cache_dir = project['windows_cache_dir']
    max_retries = project['max_retries']
    
    # 获取服务器目录名
    last_dir = posixpath.basename(server_dir.rstrip('/'))
    
    logger.info(f"开始原子传输项目: {ip}:{port} - {server_dir}")
    logger.info(f"最大重试次数: {max_retries}")
    
    # 初始化变量
    ssh = None
    sftp = None
    remote_tar_path = None
    local_tar_path = None
    extract_path = None
    tar_filename = None
    
    for attempt in range(1, max_retries + 1):
        try:
            logger.info(f"尝试第 {attempt}/{max_retries} 次传输")
            
            # 步骤1: 建立SSH连接
            logger.info("步骤1: 建立SSH连接")
            ssh = create_ssh_client(ip, user, password, port)
            logger.info("SSH连接成功")
            
            # 步骤2: 在Linux服务器上压缩目录
            logger.info("步骤2: 压缩远程目录")
            remote_tar_path, tar_filename = compress_remote_directory(ssh, server_dir, linux_cache_dir)
            
            if not remote_tar_path or not tar_filename:
                logger.error("压缩远程目录失败，开始重试")
                cleanup_remote_files(ssh, remote_tar_path)
                ssh.close()
                ssh = None
                time.sleep(2)  # 等待后重试
                continue
            
            # 步骤3: 打开SFTP会话
            logger.info("步骤3: 打开SFTP会话")
            sftp = ssh.open_sftp()
            
            # 步骤4: 下载压缩文件到Windows缓存目录
            logger.info("步骤4: 下载压缩文件")
            local_tar_path = download_compressed_file(sftp, remote_tar_path, windows_cache_dir, tar_filename)
            
            if not local_tar_path:
                logger.error("下载压缩文件失败，开始重试")
                cleanup_remote_files(ssh, remote_tar_path)
                cleanup_local_files(local_tar_path, extract_path)
                sftp.close()
                ssh.close()
                ssh = None
                sftp = None
                time.sleep(2)
                continue
            
            # 步骤5: 关闭SFTP和SSH连接
            logger.info("步骤5: 关闭远程连接")
            sftp.close()
            ssh.close()
            ssh = None
            sftp = None
            
            # 步骤6: 在Windows缓存目录解压文件
            logger.info("步骤6: 解压文件")
            extract_path = extract_tar_file(local_tar_path, windows_cache_dir)
            
            if not extract_path:
                logger.error("解压文件失败，开始重试")
                cleanup_local_files(local_tar_path, extract_path)
                time.sleep(2)
                continue
            
            # 步骤7: 创建日期格式文件夹
            logger.info("步骤7: 创建日期格式文件夹")
            date_dir = create_date_format_folder(pc_base_dir)
            
            if not date_dir:
                logger.error("创建日期格式文件夹失败，开始重试")
                cleanup_local_files(local_tar_path, extract_path)
                time.sleep(2)
                continue
            
            # 步骤8: 原子移动到日期格式文件夹
            logger.info("步骤8: 原子移动目录")
            move_success = atomic_move_directory(extract_path, date_dir, last_dir)
            
            if not move_success:
                logger.error("原子移动目录失败，开始重试")
                cleanup_local_files(local_tar_path, extract_path)
                time.sleep(2)
                continue
            
            # 步骤9: 清理临时文件
            logger.info("步骤9: 清理临时文件")
            
            # 重新连接以清理远程文件
            ssh = create_ssh_client(ip, user, password, port)
            cleanup_remote_files(ssh, remote_tar_path)
            ssh.close()
            
            cleanup_local_files(local_tar_path, None)  # extract_path已被移动，不需要清理
            
            logger.info(f"原子传输成功完成!")
            return {'success': True, 'attempts': attempt}
            
        except Exception as e:
            logger.error(f"第 {attempt} 次尝试失败: {str(e)}")
            logger.error(traceback.format_exc())
            
            # 清理资源
            if sftp:
                try:
                    sftp.close()
                except:
                    pass
            
            if ssh:
                try:
                    ssh.close()
                except:
                    pass
            
            # 清理临时文件
            if ssh and remote_tar_path:
                try:
                    new_ssh = create_ssh_client(ip, user, password, port)
                    cleanup_remote_files(new_ssh, remote_tar_path)
                    new_ssh.close()
                except:
                    pass
            
            cleanup_local_files(local_tar_path, extract_path)
            
            if attempt < max_retries:
                logger.info(f"等待 5 秒后重试...")
                time.sleep(5)
            else:
                logger.error(f"已达到最大重试次数 ({max_retries})，传输失败")
    
    return {'success': False, 'attempts': max_retries}

def main():
    """主函数，处理所有项目"""
    # 加载配置文件
    load_projects_from_config()
    
    if not projects:
        logger.error("没有可用的项目配置，无法继续执行")
        input("按 Enter 键退出程序...")
        exit(1)
    
    logger.info(f"共加载 {len(projects)} 个项目")
    
    # 收集所有项目的统计
    all_results = []
    
    for idx, project in enumerate(projects, start=1):
        ip = project['ip']
        server_dir = project['server_dir']
        max_retries = project['max_retries']
        
        logger.info(f"开始处理任务[{idx}]: {ip} - {server_dir}")
        logger.info(f"最大重试次数: {max_retries}")
        
        # 执行原子传输
        result = atomic_transfer_project(project)
        
        # 记录结果
        if result['success']:
            logger.info(f"任务[{idx}] 成功完成，尝试次数: {result['attempts']}")
            all_results.append(f"任务[{idx}] - 成功 (尝试次数: {result['attempts']})")
        else:
            logger.error(f"任务[{idx}] 失败，达到最大重试次数")
            all_results.append(f"任务[{idx}] - 失败 (达到最大重试次数: {max_retries})")
    
    # 输出所有任务结果
    logger.info("所有任务完成。以下是结果：")
    for result in all_results:
        logger.info(result)
    
    # 统计成功和失败的任务
    success_count = sum(1 for r in all_results if "成功" in r)
    fail_count = len(all_results) - success_count
    
    logger.info(f"任务统计: 共 {len(all_results)} 个任务, {success_count} 个成功, {fail_count} 个失败")

# 主程序入口
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("用户中断程序")
    except Exception as e:
        logger.error(f"程序运行异常: {str(e)}")
        logger.error(traceback.format_exc())
    
    input("按 Enter 键退出程序...")