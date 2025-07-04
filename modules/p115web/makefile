#安装后端依赖
install-py:
	pip3 install -U -r requirements.txt

#安装前端依赖
install-f:
	cd frontend && pnpm i

#启动前端
dev-f:
	cd frontend && pnpm dev &

#启动后端
dev-b:
	python3 start.py

#前端打包
build:
	cd frontend && npm run build

#启动前后端
dev:dev-f dev-b

#安装前后端依赖
install:install-py install-f

#启动前后端
dev2:
	concurrently --kill-others-on-fail "make dev-f" "make dev-b"
dev-b2:
	concurrently --kill-others-on-fail "make dev-b"

#安装后端依赖2
install-py2:
	concurrently --kill-others-on-fail "make install-py"
