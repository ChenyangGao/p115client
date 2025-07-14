#!/usr/bin/env python3
# encoding: utf-8

def echo_author():
    # http://patorjk.com/software/taag/#p=display&f=ANSI%20Shadow&t=p115%20web
    print("""
██████╗  ██╗ ██╗███████╗    ██╗    ██╗███████╗██████╗ 
██╔══██╗███║███║██╔════╝    ██║    ██║██╔════╝██╔══██╗
██████╔╝╚██║╚██║███████╗    ██║ █╗ ██║█████╗  ██████╔╝
██╔═══╝  ██║ ██║╚════██║    ██║███╗██║██╔══╝  ██╔══██╗
██║      ██║ ██║███████║    ╚███╔███╔╝███████╗██████╔╝
╚═╝      ╚═╝ ╚═╝╚══════╝     ╚══╝╚══╝ ╚══════╝╚═════╝
""")

def startup():
    echo_author()
    print(f'程序启动成功')

def main():
    from .file_lister import main
    startup()
    main()

if __name__ == "__main__":
    from pathlib import Path
    from sys import path

    path[0] = str(Path(__file__).parents[1])
    main()

# TODO: 后端使用 p115dav + 一个扩展的前端

