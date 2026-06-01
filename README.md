# ACCHunter 用户使用说明

ACCHunter 是一个面向 Android APK 的安全分析系统。用户可以通过 Web 前端上传 APK，系统会在后端执行第三方库识别和漏洞分析，并在页面中显示任务状态、实时日志和最终报告。

系统包含：

- `api`：FastAPI 后端，同时提供前端页面、API 和 WebSocket 日志通道。
- `worker`：Celery 分析任务执行器，负责真正调用扫描引擎。
- `redis`：任务队列和结果后端。
- `postgres`：任务和报告元数据数据库。

## 推荐部署顺序

请按下面顺序准备系统：

1. 先在本机/WSL 中准备 `data/` 数据和缓存。
2. 确认 `data/` 不会进入 Docker 镜像。
3. 再构建 Docker 镜像。
4. 最后启动前端、后端和 worker。

这样做可以避免 Docker 镜像过大，也可以避免系统第一次运行时临时生成大量缓存导致电脑卡顿。

## 1. 准备本机依赖

推荐在 Linux 或 WSL 的项目根目录中执行。

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

确认 Java 可用：

```bash
java -version
```

如果需要控制缓存生成时的 CPU 占用，可以先设置并发。下面示例使用 11 个进程；如果机器较慢，可以改成 4 或 6。

```bash
export LIBHUNTER_PROCESSES=11
export LH_MAX_THREAD_NUM=11
```

## 2. 准备 data 目录

`data/` 是系统分析所需的数据和缓存目录，必须保留，但不能打包进 Docker 镜像。

先创建目录：

```bash
mkdir -p \
  data/lib_pickles_cache \
  data/apk_pickles_cache \
  data/lib_pickles_skeleton \
  data/lib_pickles_buckets \
  data/phunter_soot_cache \
  storage/logs \
  outputs/raw
```

常用目录说明：

```text
data/tpl_dex                  LibHunter 第三方库 dex 特征
data/tpl_jar                  可选，LibHunter 第三方库 jar 特征
data/lib_pickles_cache        LibHunter 版本级缓存
data/lib_pickles_skeleton     LibHunter 骨架级缓存
data/lib_pickles_buckets      LibHunter 桶缓存
data/apk_pickles_cache        APK 作用域缓存
data/phunter_soot_cache       PHunter 模板/soot 缓存
data/patches                  漏洞补丁数据
data/cve_kb.json              漏洞知识库
```

如果你已经拿到了完整的 `data/` 目录，并且里面已经有这些缓存，可以跳过下面的缓存生成步骤，直接进入 Docker 构建。

## 3. 生成 LibHunter 版本级缓存

版本级缓存来自 `data/tpl_dex`，输出到 `data/lib_pickles_cache`。

```bash
mkdir -p /tmp/acchunter-empty-apks outputs/libhunter_prewarm

python3 LibHunter/LibHunter.py detect_all \
  -o outputs/libhunter_prewarm \
  -af /tmp/acchunter-empty-apks \
  -p ${LIBHUNTER_PROCESSES:-11} \
  -ld data/tpl_dex
```

如果存在 `data/tpl_jar`，可以加上 `-lf data/tpl_jar`：

```bash
python3 LibHunter/LibHunter.py detect_all \
  -o outputs/libhunter_prewarm \
  -af /tmp/acchunter-empty-apks \
  -p ${LIBHUNTER_PROCESSES:-11} \
  -ld data/tpl_dex \
  -lf data/tpl_jar
```

说明：

- `-ld data/tpl_dex`：第三方库 dex 特征目录。
- `-af /tmp/acchunter-empty-apks`：空 APK 目录，用于只触发模板 pickle 构建。
- `-p`：并行进程数，数值越高越快，但 CPU 占用越高。

## 4. 生成 LibHunter 骨架级缓存

骨架级缓存来自版本级缓存，输出到 `data/lib_pickles_skeleton`。

```bash
python3 LibHunter/LibHunter.py build_skeleton \
  -p data/lib_pickles_cache \
  -o data/lib_pickles_skeleton \
  --overwrite
```

## 5. 生成 LibHunter 桶缓存

桶缓存输出到 `data/lib_pickles_buckets`。当前项目提供了 Guava、Jackson、Kotlin 的桶缓存生成入口。

```bash
python3 LibHunter/LibHunter.py build_guava_bucket \
  -p data/lib_pickles_cache \
  --tpl-dex-dir data/tpl_dex \
  -o data/lib_pickles_buckets \
  --overwrite
```

```bash
python3 LibHunter/LibHunter.py build_jackson_bucket \
  -p data/lib_pickles_cache \
  --tpl-dex-dir data/tpl_dex \
  -o data/lib_pickles_buckets \
  --overwrite
```

```bash
python3 LibHunter/LibHunter.py build_kotlin_bucket \
  -p data/lib_pickles_cache \
  --tpl-dex-dir data/tpl_dex \
  -o data/lib_pickles_buckets \
  --overwrite
```

## 6. 生成 PHunter 模板缓存

PHunter 模板缓存来自 `data/cve_kb.json`、`data/patches` 和 PHunter 分析逻辑，输出到 `data/phunter_soot_cache`。

```bash
python3 main.py --prewarm-phunter
```

如果只想先试运行一小部分，可以限制数量：

```bash
python3 main.py --prewarm-phunter --prewarm-limit 10
```

## 7. 生成 APK 作用域缓存

`data/apk_pickles_cache` 是 APK 作用域缓存，通常会在扫描 APK 时自动生成或复用。

如果需要提前为某个 APK 生成，可以先把 APK 放到 `storage/uploads/`，然后执行：

```bash
python3 main.py --apk storage/uploads/your.apk
```

请把 `your.apk` 替换成真实 APK 文件名。

## 8. 确认 data 不进入 Docker 镜像

`.dockerignore` 必须包含：

```text
data/
storage/
outputs/
inputs/
.venv/
frontend/node_modules/
```

尤其不要移除 `data/`。`data/` 只应该在运行容器时通过 volume 挂载，不应该进入镜像。

当前 Docker 运行时会把本机 `data/` 只读挂载到容器内：

```text
./data:/app/data:ro
```

缓存环境变量默认指向：

```text
DATA_DIR=/app/data
PICKLE_CACHE_DIR=/app/data/lib_pickles_cache
APK_PICKLE_CACHE_DIR=/app/data/apk_pickles_cache
SKELETON_PICKLE_CACHE_DIR=/app/data/lib_pickles_skeleton
BUCKET_PICKLE_CACHE_DIR=/app/data/lib_pickles_buckets
PHUNTER_CACHE_DIR=/app/data/phunter_soot_cache
```

这意味着：

- Docker 镜像不会因为 `data/` 变得很大。
- 系统运行时可以直接读取本机已经生成好的缓存。
- 容器不能写入或破坏 `data/`。

## 9. 构建 Docker 镜像

确认缓存准备好后，再构建镜像：

```bash
docker compose -p acchunter build
```

构建时可以观察 build context 大小。如果 `.dockerignore` 生效，build context 不应该是十几 GB。

## 10. 启动系统

```bash
docker compose -p acchunter up -d
```

启动后访问：

```text
http://127.0.0.1:8000/
```

查看服务状态：

```bash
docker compose -p acchunter ps
```

## 前端使用流程

1. 打开 `http://127.0.0.1:8000/`。
2. 进入上传页面，选择 `.apk` 文件。
3. 点击上传并提交分析。
4. 进入任务执行页面后，可以查看：
   - 当前任务 ID
   - 任务状态
   - WebSocket 实时日志
   - 扫描完成后的 JSON 报告

任务状态含义：

- `queued`：任务已进入队列，等待 worker 执行。
- `running`：worker 正在分析 APK。
- `completed`：分析完成，可以查看报告。
- `failed`：分析失败，可以查看页面错误信息和日志文件。

## CPU 使用限制

分析 APK 时，LibHunter/PHunter 可能会进行并行计算，CPU 占用会明显升高。

当前默认配置将 worker 限制为最多使用 11 个 CPU。对于 Docker 显示 `22 CPUs available` 的机器，这相当于一半 CPU：

```yaml
worker:
  cpus: ${WORKER_CPUS:-11}
```

LibHunter 并行进程数也默认限制为 11：

```text
LIBHUNTER_PROCESSES=11
```

如果电脑仍然卡，可以在 `.env` 中降低：

```text
WORKER_CPUS=4
LIBHUNTER_PROCESSES=4
```

修改后重启 worker：

```bash
docker compose -p acchunter up -d --force-recreate worker
```

## WebSocket 日志

前端执行页面通过 WebSocket 连接后端日志通道：

```text
/api/logs?task_id=<task_id>
```

如果页面显示 `WS 重连中` 或 `WebSocket 连接出现异常`，可以先检查 API 日志：

```bash
docker compose -p acchunter logs --tail=100 api
```

正常情况下日志中会出现：

```text
WebSocket /api/logs?task_id=... [accepted]
connection open
```

## 常用管理命令

查看 API 日志：

```bash
docker compose -p acchunter logs -f api
```

查看 worker 日志：

```bash
docker compose -p acchunter logs -f worker
```

查看资源占用：

```bash
docker stats
```

停止系统：

```bash
docker compose -p acchunter stop
```

再次启动系统：

```bash
docker compose -p acchunter up -d
```

如果页面能打开但任务一直排队，通常是 worker 没启动：

```bash
docker compose -p acchunter up -d worker
```

如果 `acchunter-worker-1` CPU 很高，可以先暂停 worker：

```bash
docker stop acchunter-worker-1
```

## API 调用示例

上传 APK：

```bash
curl -F "file=@/path/to/app.apk" http://127.0.0.1:8000/api/upload
```

提交分析：

```bash
curl -X POST http://127.0.0.1:8000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"filename":"app.apk"}'
```

查询任务：

```bash
curl http://127.0.0.1:8000/api/tasks/<task_id>
```

查询报告：

```bash
curl http://127.0.0.1:8000/api/tasks/<task_id>/report
```

健康检查：

```bash
curl http://127.0.0.1:8000/api/health
```

## 不要误删数据

不要随便执行会删除大量 Docker 资源的命令，尤其是不了解影响时不要执行：

```bash
docker system prune -a --volumes
```

如果只是停止系统，使用：

```bash
docker compose -p acchunter stop
```

如果只是删除 acchunter 容器但保留项目文件：

```bash
docker compose -p acchunter down
```

项目根目录下的 `data/` 是宿主机文件夹，不属于镜像，不应该删除。

