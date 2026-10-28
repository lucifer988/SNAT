#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gunicorn 入口：gunicorn --chdir /opt/snat-manager web.wsgi:app

用单 worker + 多线程：登录锁定/限流/日志缓冲是进程内内存态，多 worker 会各自为政
（锁定与限流被放大 N 倍）。线程并发足够撑一个管理面板，且 SQLite WAL + 每请求新连接是线程安全的。
"""
from web.app import app, bootstrap

bootstrap()
