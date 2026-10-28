#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gunicorn 入口：gunicorn --chdir <agent 目录> wsgi:app

注意：必须用单 worker（避免多进程同时改 iptables / 重复跑 DNS 线程）。
不要开 --preload，否则 DNS 刷新线程会留在 master 进程、fork 后丢失。
"""
import agent as _agent

_agent.bootstrap()
app = _agent.app
