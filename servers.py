#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
完整脚本：支持远程 Linux (tar.gz) and Windows (直接通过 SFTP 递归下载目录，不压缩)
行为：
- 远程为 Linux：仍使用 tar.gz 压缩 -> 下载 -> 解压 -> 原子移动
- 远程为 Windows：绕开压缩，直接用 SFTP 递归下载 server_dir 的内容到本地缓存目录 -> 原子移动
注意：此脚本尽力处理 Windows 路径变体并尝试找出可被 SFTP 访问的远程路径。
"""

import paramiko
from datetime import datetime
import os
import logging
import configparser
import time
import random
import string
import shutil
import tarfile
import posixpath
import ntpath
import traceback
import stat as statmod
import zipfile

# 日志配置：输出到控制台
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger()

projects = []

def load_projects_from_config(config_file='servers.cfg'):
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
            ip = config[section].get('ip', '').strip().strip('"')
            user = config[section].get('user', '').strip().strip('"')
            password = config[section].get('password', '').strip().strip('"')
            server_dir = config[section].get('server_dir', '').strip().strip('"')
            pc_dir = config[section].get('pc_dir', '').strip().strip('"')
            port = config[section].get('port', '22').strip().strip('"')
            linux_cache_dir = config[section].get('linux_cache_dir', '/tmp').strip().strip('"')
            windows_cache_dir = config[section].get('windows_cache_dir', 'C:\\Temp').strip().strip('"')
            max_retries = config[section].get('max_retries', '3').strip().strip('"')

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
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def create_ssh_client(ip, user, password, port, timeout=30):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(ip, username=user, password=password, port=port, timeout=timeout)
    return ssh

def execute_remote_command(ssh, command, timeout=None):
    stdin, stdout, stderr = ssh.exec_command(command, timeout=timeout)
    exit_status = stdout.channel.recv_exit_status()
    output = stdout.read().decode('utf-8', errors='ignore').strip()
    error = stderr.read().decode('utf-8', errors='ignore').strip()
    return exit_status, output, error

def detect_remote_os(ssh):
    try:
        exit_status, output, error = execute_remote_command(ssh, "uname -s")
        if exit_status == 0 and output:
            lower = output.lower()
            if 'linux' in lower or 'darwin' in lower or 'unix' in lower:
                logger.info(f"远程系统检测: 类 Unix ({output})")
                return 'linux'
        ps_cmd = 'powershell -NoProfile -Command "Write-Output $PSVersionTable.PSVersion.Major"'
        exit_status, output, error = execute_remote_command(ssh, ps_cmd)
        if exit_status == 0 and output:
            logger.info(f"远程系统检测: Windows (PowerShell 可用, output={output})")
            return 'windows'
        exit_status, output, error = execute_remote_command(ssh, 'cmd.exe /c ver')
        if exit_status == 0 and (('windows' in output.lower()) or ('microsoft' in output.lower())):
            logger.info(f"远程系统检测: Windows (cmd ver 输出: {output})")
            return 'windows'
        logger.warning("无法明确检测远程操作系统，默认按 linux 处理")
        return 'linux'
    except Exception as e:
        logger.warning(f"检测远程操作系统时出错，默认按 linux。错误: {e}")
        return 'linux'

def compress_remote_directory_linux(ssh, server_dir, linux_cache_dir):
    """Linux: 压缩并返回单条远程路径和文件名"""
    try:
        dir_name = posixpath.basename(server_dir.rstrip('/'))
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        random_str = generate_random_string(6)
        tar_filename = f"{dir_name}_{timestamp}_{random_str}.tar.gz"
        tar_path = posixpath.join(linux_cache_dir, tar_filename)
        parent_dir = posixpath.dirname(server_dir.rstrip('/')) or '/'
        compress_cmd = f"cd '{parent_dir}' && tar -czf '{tar_path}' '{dir_name}'"
        logger.info(f"开始压缩远程 Linux 目录: {server_dir} -> {tar_path}")
        exit_status, output, error = execute_remote_command(ssh, compress_cmd)
        if exit_status != 0:
            logger.error(f"Linux 压缩失败: exit_status={exit_status}, error={error}")
            return None, None
        check_cmd = f"ls -la '{tar_path}' 2>/dev/null || echo 'NOT_FOUND'"
        exit_status, output, error = execute_remote_command(ssh, check_cmd)
        if 'NOT_FOUND' in output:
            logger.error(f"压缩文件未创建成功: {tar_path}")
            return None, None
        logger.info(f"压缩成功: {tar_path}")
        return tar_path, tar_filename
    except Exception as e:
        logger.error(f"Linux 压缩过程中发生错误: {e}")
        logger.error(traceback.format_exc())
        return None, None

def _generate_remote_path_variants(remote_path):
    variants = []
    if not remote_path:
        return variants
    variants.append(remote_path)
    variants.append(remote_path.replace('\\', '/'))
    variants.append(remote_path.replace('/', '\\'))
    try:
        if ':' in remote_path:
            drive = remote_path.split(':', 1)[0]
            rest = remote_path.split(':', 1)[1]
            variants.append('/' + drive + ':' + rest.replace('\\', '/'))
            variants.append('/' + drive.lower() + ':' + rest.replace('\\', '/'))
            variants.append('/' + drive + rest.replace(':', '').replace('\\', '/'))
            variants.append('/' + drive.lower() + rest.replace(':', '').replace('\\', '/'))
    except Exception:
        pass
    if remote_path.startswith('/') or remote_path.startswith('\\'):
        variants.append(remote_path.lstrip('/\\'))
    if remote_path.startswith('\\\\?\\'):
        variants.append(remote_path[4:])
    unique = []
    for v in variants:
        if v not in unique:
            unique.append(v)
    return unique

def find_existing_remote_dir(sftp, server_dir):
    """
    尝试在 sftp 上找到一个可 access 的目录变体，返回第一个可用的 remote_dir（字符串），否则返回 None
    """
    candidates = _generate_remote_path_variants(server_dir)
    logger.info(f"查找可用远程目录候选: {candidates}")
    for cand in candidates:
        try:
            # 尝试 stat 并判断是否为目录
            try:
                st = sftp.stat(cand)
                if statmod.S_ISDIR(st.st_mode):
                    logger.info(f"找到可用远程目录 (stat): {cand}")
                    return cand
                else:
                    logger.debug(f"候选存在但不是目录: {cand}")
                    continue
            except IOError:
                # stat 失败，再尝试 listdir 看能否列出（有时 stat 不被允许）
                try:
                    items = sftp.listdir(cand)
                    logger.info(f"找到可用远程目录 (listdir): {cand} (items count {len(items)})")
                    return cand
                except Exception as e:
                    logger.debug(f"listdir 失败 ({cand}): {e}")
                    continue
        except Exception as e:
            logger.debug(f"尝试候选目录 {cand} 发生异常: {e}")
            continue
    # 备用策略：尝试把路径当作 Windows 风格的驱动器父级查找（例如去掉最后一段，逐步向上列目录）
    try:
        parent = server_dir
        for _ in range(5):
            parent = parent.rstrip('\\/')

            if '\\' in parent:
                parent = ntpath.dirname(parent)
            else:
                parent = posixpath.dirname(parent)

            if not parent:
                break
            cand_variants = _generate_remote_path_variants(parent)
            for cv in cand_variants:
                try:
                    items = sftp.listdir(cv)
                    logger.info(f"通过父级寻找到可列目录: {cv}")
                    # 如果能列出 parent，则尝试 server_dir as child name variant
                    # 组合 child
                    child_name = server_dir.split(parent)[-1].lstrip('\\/').lstrip('/')
                    alt = cv + ('\\' if '\\' in cv else '/') + child_name
                    try:
                        if statmod.S_ISDIR(sftp.stat(alt).st_mode):
                            logger.info(f"组合后发现目录: {alt}")
                            return alt
                    except Exception:
                        try:
                            if sftp.listdir(alt) is not None:
                                logger.info(f"组合后发现目录 (listdir): {alt}")
                                return alt
                        except:
                            pass
                except Exception:
                    pass
    except Exception:
        pass
    logger.warning("未能在远程 SFTP 上找到可访问的目录变体")
    return None

def remote_join(remote_dir, name):
    """根据 remote_dir 的分隔风格拼接子路径"""
    if '\\' in remote_dir:
        return remote_dir.rstrip('\\') + '\\' + name
    else:
        return remote_dir.rstrip('/') + '/' + name

def download_remote_directory(sftp, remote_dir, local_dir):
    """
    递归下载远程目录内容到本地目录。
    remote_dir: 已确认可访问的远程目录路径（字符串）
    local_dir: 本地目标目录（将会在该目录下创建内容）
    返回 True/False
    """
    try:
        logger.info(f"开始递归下载远程目录: {remote_dir} -> 本地 {local_dir}")
        # 确保本地目录存在
        os.makedirs(local_dir, exist_ok=True)
        # 使用 listdir_attr 获取文件属性
        items = sftp.listdir_attr(remote_dir)
        for attr in items:
            name = attr.filename
            # 跳过 '.' 和 '..'
            if name in ('.', '..'):
                continue
            remote_path = remote_join(remote_dir, name)
            local_path = os.path.join(local_dir, name)
            try:
                mode = attr.st_mode
                if statmod.S_ISDIR(mode):
                    # 目录：递归
                    logger.info(f"创建并进入本地目录: {local_path}")
                    os.makedirs(local_path, exist_ok=True)
                    download_remote_directory(sftp, remote_path, local_path)
                else:
                    # 文件：下载
                    logger.info(f"下载文件: {remote_path} -> {local_path}")
                    # 如果文件已存在且大小相同可以跳过（节约带宽）
                    try:
                        if os.path.exists(local_path) and os.path.getsize(local_path) == attr.st_size:
                            logger.info(f"本地已存在且大小相同，跳过: {local_path}")
                            continue
                    except Exception:
                        pass
                    # 进行下载（按块）
                    with sftp.open(remote_path, 'rb') as rf, open(local_path, 'wb') as lf:
                        while True:
                            chunk = rf.read(32768)
                            if not chunk:
                                break
                            lf.write(chunk)
                    # 尝试设置本地文件时间为远程文件时间（如果可用）
                    try:
                        atime = attr.st_atime if hasattr(attr, 'st_atime') else None
                        mtime = attr.st_mtime if hasattr(attr, 'st_mtime') else None
                        if mtime:
                            os.utime(local_path, (atime or mtime, mtime))
                    except Exception:
                        pass
            except Exception as e_item:
                logger.warning(f"处理远程项失败: {remote_path}, 错误: {e_item}")
                continue
        return True
    except Exception as e:
        logger.error(f"递归下载失败: {e}")
        logger.error(traceback.format_exc())
        return False

def download_compressed_file_sftp_variants(sftp, remote_archive_paths, local_cache_dir, archive_filename):
    """
    兼容旧流程：尝试下载一组远程压缩路径候选（保留用于 Linux tar.gz 下载）
    """
    try:
        os.makedirs(local_cache_dir, exist_ok=True)
        local_archive_path = os.path.join(local_cache_dir, archive_filename)
        if not isinstance(remote_archive_paths, (list, tuple)):
            remote_archive_paths = [remote_archive_paths]
        for base in remote_archive_paths:
            variants = _generate_remote_path_variants(base)
            for cand in variants:
                try:
                    logger.info(f"尝试访问远程压缩路径: '{cand}'")
                    try:
                        st = sftp.stat(cand)
                        logger.info(f"远程文件存在 (stat): {cand} (size={getattr(st, 'st_size', 'unknown')})")
                        sftp.get(cand, local_archive_path)
                        if os.path.exists(local_archive_path) and os.path.getsize(local_archive_path) > 0:
                            logger.info(f"通过 sftp.get 下载成功: {local_archive_path} (candidate: {cand})")
                            return local_archive_path
                        else:
                            logger.warning(f"下载后文件不存在或大小为0: {local_archive_path}")
                            try: os.remove(local_archive_path)
                            except: pass
                    except IOError as e_stat:
                        logger.debug(f"stat 失败 ({cand}): {e_stat}; 尝试 open 读取")
                        try:
                            with sftp.open(cand, 'rb') as remote_f, open(local_archive_path, 'wb') as lf:
                                while True:
                                    chunk = remote_f.read(32768)
                                    if not chunk:
                                        break
                                    lf.write(chunk)
                            if os.path.exists(local_archive_path) and os.path.getsize(local_archive_path) > 0:
                                logger.info(f"通过 sftp.open 下载成功: {local_archive_path} (candidate: {cand})")
                                return local_archive_path
                            else:
                                logger.warning(f"通过 open 下载后文件为空: {local_archive_path}")
                                try: os.remove(local_archive_path)
                                except: pass
                        except Exception as e_open:
                            logger.debug(f"open 读取失败 ({cand}): {e_open}")
                            pass
                except Exception as e_inner:
                    logger.debug(f"尝试候选路径 {cand} 发生异常: {e_inner}")
                    continue
        logger.error("无法下载任何候选的压缩文件")
        return None
    except Exception as e:
        logger.error(f"下载压缩文件过程出错: {e}")
        logger.error(traceback.format_exc())
        return None

def extract_archive(local_archive_path, local_cache_dir):
    try:
        if not local_archive_path or not os.path.exists(local_archive_path):
            logger.error(f"解压失败：文件不存在 {local_archive_path}")
            return None
        name = os.path.basename(local_archive_path)
        if name.endswith('.tar.gz') or name.endswith('.tgz'):
            extract_dir_name = os.path.splitext(os.path.splitext(name)[0])[0]
        else:
            extract_dir_name = os.path.splitext(name)[0]
        extract_path = os.path.join(local_cache_dir, extract_dir_name)
        logger.info(f"开始解压文件: {local_archive_path} -> {extract_path}")
        if os.path.exists(extract_path):
            shutil.rmtree(extract_path)
        os.makedirs(extract_path, exist_ok=True)
        if name.endswith('.tar.gz') or name.endswith('.tgz'):
            with tarfile.open(local_archive_path, 'r:gz') as tar:
                tar.extractall(path=extract_path)
        elif name.endswith('.zip'):
            with zipfile.ZipFile(local_archive_path, 'r') as zipf:
                zipf.extractall(path=extract_path)
        else:
            logger.error(f"不支持的压缩格式: {name}")
            return None
        if os.path.exists(extract_path) and len(os.listdir(extract_path)) > 0:
            logger.info(f"解压成功: {extract_path}")
            return extract_path
        else:
            logger.error(f"解压失败或目录为空: {extract_path}")
            return None
    except Exception as e:
        logger.error(f"解压过程中发生错误: {e}")
        logger.error(traceback.format_exc())
        return None

def create_date_format_folder(pc_dir):
    try:
        now = datetime.now()
        current_date = f"{now.year}-{now.month:02d}-{now.day:02d}"
        date_dir = os.path.join(pc_dir, current_date)
        logger.info(f"创建日期格式文件夹: {date_dir}")
        os.makedirs(date_dir, exist_ok=True)
        return date_dir
    except Exception as e:
        logger.error(f"创建日期格式文件夹失败: {e}")
        logger.error(traceback.format_exc())
        return None

def atomic_move_directory(source_dir, target_parent_dir, last_dir_name):
    try:
        target_dir = os.path.join(target_parent_dir, last_dir_name)
        logger.info(f"原子移动目录: {source_dir} -> {target_dir}")
        backup_dir = None
        if os.path.exists(target_dir):
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            random_str = generate_random_string(4)
            backup_dir = f"{target_dir}_backup_{timestamp}_{random_str}"
            logger.info(f"目标目录已存在，重命名为备份: {backup_dir}")
            os.rename(target_dir, backup_dir)
        shutil.move(source_dir, target_dir)
        if os.path.exists(target_dir) and not os.path.exists(source_dir):
            logger.info(f"原子移动成功: {target_dir}")
            if backup_dir and os.path.exists(backup_dir):
                try:
                    shutil.rmtree(backup_dir)
                    logger.info(f"删除备份目录: {backup_dir}")
                except Exception as e:
                    logger.warning(f"删除备份失败: {backup_dir}, {e}")
            return True
        else:
            logger.error("原子移动失败: 源目录仍存在或目标目录不存在")
            if backup_dir and os.path.exists(backup_dir):
                try:
                    os.rename(backup_dir, target_dir)
                    logger.info(f"恢复备份目录: {target_dir}")
                except Exception as e:
                    logger.error(f"恢复备份失败: {e}")
            return False
    except Exception as e:
        logger.error(f"原子移动过程中发生错误: {e}")
        logger.error(traceback.format_exc())
        return False

def cleanup_remote_files(ssh, remote_paths):
    """尝试删除多个远程路径（字符串或列表）"""
    try:
        if not ssh or not remote_paths:
            return
        if not isinstance(remote_paths, (list, tuple)):
            remote_paths = [remote_paths]
        remote_os = detect_remote_os(ssh)
        for p in remote_paths:
            try:
                if remote_os == 'linux':
                    cmd = f"rm -f '{p}'"
                    execute_remote_command(ssh, cmd)
                else:
                    ps = f"powershell -NoProfile -Command 'if (Test-Path -LiteralPath \"{p}\") {{ Remove-Item -LiteralPath \"{p}\" -Force }}'"
                    execute_remote_command(ssh, ps)
                logger.info(f"尝试清理远程文件: {p}")
            except Exception as e:
                logger.warning(f"清理远程文件时发生错误 ({p}): {e}")
    except Exception as e:
        logger.warning(f"清理远程文件时发生错误: {e}")

def cleanup_local_files(local_archive_path, extract_path):
    try:
        if local_archive_path and os.path.exists(local_archive_path):
            try:
                os.remove(local_archive_path)
                logger.info(f"清理本地压缩文件: {local_archive_path}")
            except Exception as e:
                logger.warning(f"删除本地压缩文件失败: {e}")
        if extract_path and os.path.exists(extract_path):
            try:
                shutil.rmtree(extract_path)
                logger.info(f"清理本地解压目录: {extract_path}")
            except Exception as e:
                logger.warning(f"删除本地解压目录失败: {e}")
    except Exception as e:
        logger.warning(f"清理本地文件时发生错误: {e}")

def atomic_transfer_project(project):
    ip = project['ip']
    user = project['user']
    password = project['password']
    server_dir = project['server_dir']
    pc_base_dir = project['pc_dir']
    port = project['port']
    linux_cache_dir = project['linux_cache_dir']
    windows_cache_dir = project['windows_cache_dir']
    max_retries = project['max_retries']
    last_dir = ntpath.basename(server_dir.rstrip('\\').rstrip('/')) or posixpath.basename(server_dir.rstrip('/'))
    logger.info(f"开始原子传输项目: {ip}:{port} - {server_dir}")
    logger.info(f"最大重试次数: {max_retries}")

    for attempt in range(1, max_retries + 1):
        ssh = None
        sftp = None
        remote_archive_or_dir = None
        local_temp_archive = None
        local_extract_path = None
        try:
            logger.info(f"尝试第 {attempt}/{max_retries} 次传输")
            # 建立 SSH 连接
            logger.info("步骤1: 建立SSH连接")
            ssh = create_ssh_client(ip, user, password, port)
            logger.info("SSH连接成功")
            # 检测 OS
            remote_os = detect_remote_os(ssh)
            logger.info(f"远程操作系统: {remote_os}")

            if remote_os == 'linux':
                # Linux: 原来流程（压缩 -> 下载 -> 解压）
                logger.info("步骤2 (Linux): 压缩远程目录")
                remote_tar_path, tar_filename = compress_remote_directory_linux(ssh, server_dir, linux_cache_dir)
                if not remote_tar_path:
                    logger.error("压缩远程目录失败，准备重试")
                    try:
                        cleanup_remote_files(ssh, remote_tar_path)
                    except:
                        pass
                    ssh.close()
                    ssh = None
                    time.sleep(2)
                    continue

                logger.info("步骤3: 打开SFTP会话")
                sftp = ssh.open_sftp()

                logger.info("步骤4: 下载压缩文件")
                local_temp_archive = download_compressed_file_sftp_variants(sftp, remote_tar_path, windows_cache_dir, tar_filename)
                if not local_temp_archive:
                    logger.error("下载压缩文件失败，开始重试")
                    try:
                        cleanup_remote_files(ssh, remote_tar_path)
                    except:
                        pass
                    cleanup_local_files(local_temp_archive, None)
                    try:
                        sftp.close()
                    except:
                        pass
                    try:
                        ssh.close()
                    except:
                        pass
                    time.sleep(2)
                    continue

                logger.info("步骤5: 关闭远程连接（压缩下载完成）")
                try: sftp.close()
                except: pass
                try: ssh.close()
                except: pass
                sftp = None
                ssh = None

                logger.info("步骤6: 解压文件")
                local_extract_path = extract_archive(local_temp_archive, windows_cache_dir)
                if not local_extract_path:
                    logger.error("解压失败，开始重试")
                    cleanup_local_files(local_temp_archive, local_extract_path)
                    time.sleep(2)
                    continue

                logger.info("步骤7: 创建日期文件夹")
                date_dir = create_date_format_folder(pc_base_dir)
                if not date_dir:
                    logger.error("创建日期文件夹失败，开始重试")
                    cleanup_local_files(local_temp_archive, local_extract_path)
                    time.sleep(2)
                    continue

                logger.info("步骤8: 原子移动目录")
                move_success = atomic_move_directory(local_extract_path, date_dir, last_dir)
                if not move_success:
                    logger.error("原子移动失败，开始重试")
                    cleanup_local_files(local_temp_archive, local_extract_path)
                    time.sleep(2)
                    continue

                # 清理远端文件
                try:
                    ssh = create_ssh_client(ip, user, password, port)
                    cleanup_remote_files(ssh, remote_tar_path)
                    try: ssh.close()
                    except: pass
                    ssh = None
                except Exception as e:
                    logger.warning(f"清理远端压缩文件时无法重连: {e}")

                cleanup_local_files(local_temp_archive, None)
                logger.info("Linux 项目传输成功完成")
                return {'success': True, 'attempts': attempt}

            else:
                # Windows: 直接通过 SFTP 递归下载目录内容（不压缩）
                logger.info("步骤2 (Windows): 跳过压缩，使用 SFTP 递归下载目录内容")
                sftp = ssh.open_sftp()
                # 先寻找一个 sftp 可以访问的目录变体
                remote_dir_candidate = find_existing_remote_dir(sftp, server_dir)
                if not remote_dir_candidate:
                    logger.error("未能定位可被 SFTP 访问的远程目录，开始重试")
                    try: sftp.close()
                    except: pass
                    try: ssh.close()
                    except: pass
                    time.sleep(2)
                    continue

                # 本地缓存目录：以 last_dir + 时间戳 命名，避免与其他并发冲突
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                random_str = generate_random_string(6)
                local_extract_dirname = f"{last_dir}_{timestamp}_{random_str}"
                local_extract_path = os.path.join(windows_cache_dir, local_extract_dirname)
                if os.path.exists(local_extract_path):
                    shutil.rmtree(local_extract_path)
                os.makedirs(local_extract_path, exist_ok=True)

                # 递归下载
                success = download_remote_directory(sftp, remote_dir_candidate, local_extract_path)
                if not success:
                    logger.error("递归下载远程目录失败，开始重试")
                    try:
                        sftp.close()
                    except:
                        pass
                    try:
                        ssh.close()
                    except:
                        pass
                    cleanup_local_files(None, local_extract_path)
                    time.sleep(2)
                    continue

                # 关闭连接（下载完成）
                try:
                    sftp.close()
                except:
                    pass
                try:
                    ssh.close()
                except:
                    pass
                sftp = None
                ssh = None

                # 创建日期文件夹并原子移动
                date_dir = create_date_format_folder(pc_base_dir)
                if not date_dir:
                    logger.error("创建日期文件夹失败，开始重试")
                    cleanup_local_files(None, local_extract_path)
                    time.sleep(2)
                    continue

                move_success = atomic_move_directory(local_extract_path, date_dir, last_dir)
                if not move_success:
                    logger.error("原子移动失败，开始重试")
                    cleanup_local_files(None, local_extract_path)
                    time.sleep(2)
                    continue

                # 清理远程临时文件（如果有需要，可尝试删除特定文件；但我们不创建压缩包，所以无需删除）
                logger.info("Windows 项目传输成功完成（未使用压缩）")
                return {'success': True, 'attempts': attempt}

        except Exception as e:
            logger.error(f"第 {attempt} 次尝试失败: {e}")
            logger.error(traceback.format_exc())
            try:
                if sftp:
                    sftp.close()
            except:
                pass
            try:
                if ssh:
                    ssh.close()
            except:
                pass
            # 尝试清理本地临时
            try:
                cleanup_local_files(local_temp_archive, local_extract_path)
            except:
                pass
            if attempt < max_retries:
                logger.info("等待 5 秒后重试...")
                time.sleep(5)
            else:
                logger.error(f"已达到最大重试次数 ({max_retries})，传输失败")
    return {'success': False, 'attempts': max_retries}

def main():
    load_projects_from_config()
    if not projects:
        logger.error("没有可用的项目配置，无法继续执行")
        input("按 Enter 键退出程序...")
        exit(1)
    logger.info(f"共加载 {len(projects)} 个项目")
    all_results = []
    for idx, project in enumerate(projects, start=1):
        ip = project['ip']
        server_dir = project['server_dir']
        max_retries = project['max_retries']
        logger.info(f"开始处理任务[{idx}]: {ip} - {server_dir}")
        logger.info(f"最大重试次数: {max_retries}")
        result = atomic_transfer_project(project)
        if result['success']:
            logger.info(f"任务[{idx}] 成功完成，尝试次数: {result['attempts']}")
            all_results.append(f"任务[{idx}] - 成功 (尝试次数: {result['attempts']})")
        else:
            logger.error(f"任务[{idx}] 失败，达到最大重试次数")
            all_results.append(f"任务[{idx}] - 失败 (达到最大重试次数: {max_retries})")
    logger.info("所有任务完成。以下是结果：")
    for result in all_results:
        logger.info(result)
    success_count = sum(1 for r in all_results if "成功" in r)
    fail_count = len(all_results) - success_count
    logger.info(f"任务统计: 共 {len(all_results)} 个任务, {success_count} 个成功, {fail_count} 个失败")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("用户中断程序")
    except Exception as e:
        logger.error(f"程序运行异常: {e}")
        logger.error(traceback.format_exc())
    input("按 Enter 键退出程序...")
