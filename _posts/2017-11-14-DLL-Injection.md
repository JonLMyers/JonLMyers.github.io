---
layout: post
title: Introduction to Reflective DLL Injection
categories: [Security]
tags: [Windows, Red Team, Development, Privilege Esc, DLL Injection, Malware, Tools]
description: An in depth introduction to writing DLL injector's from scratch!
---

DLL injection serves as an incredibly useful technique for those looking to load their custom libraries into a process and unify with it as one.  This provides developers enormous amounts of power over deployed applications and with that comes a great responsibility which is often taken advantage of.   Adversaries of all different kinds may use this post exploitation technique to establish persistence by hiding their shells within critical system processes.  By hiding within these processes adversaries are able to remain undetected much longer than being exposed on the surface of the system itself.  Additionally, adversaries can bypass firewall protections by injecting their libraries into trusted processes that have the ability to travel through the firewall.  In the rest of this post I will cover some key aspects of the DLL injection technique and write a simple injector as a proof of concept.  All code for this blog can be found on my Github at: https://github.com/JonLMyers/InjectX



