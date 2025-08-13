# 쿠버네티스(Kubernetes) 가이드

이 문서는 쿠버네티스(k8s)의 기본 개념과 구성 방법에 대해 설명합니다.

## 1. 쿠버네티스란 무엇인가?

쿠버네티스는 **컨테이너화된 애플리케이션을 자동으로 배포, 스케일링 및 관리**해주는 오픈소스 시스템입니다. 여러 호스트(서버)로 구성된 클러스터 환경에서 컨테이너를 효율적으로 운영하기 위해 개발되었습니다.

### 주요 특징
- **자동화된 롤아웃과 롤백**: 애플리케이션의 새 버전을 점진적으로 배포하거나, 문제가 발생했을 때 이전 버전으로 쉽게 되돌릴 수 있습니다.
- **서비스 디스커버리와 로드 밸런싱**: 컨테이너에 DNS 이름을 부여하거나 자체 IP 주소를 사용하여 노출하고, 트래픽을 여러 컨테이너로 분산하여 안정적인 서비스 운영을 지원합니다.
- **자동화된 복구 (Self-healing)**: 실패한 컨테이너를 자동으로 재시작하거나, 응답 없는 컨테이너를 교체하여 애플리케이션의 가용성을 높입니다.
- **스케일링**: 필요에 따라 애플리케이션이 사용하는 리소스(CPU, 메모리)를 자동으로 조절하거나, 컨테이너 인스턴스 수를 늘리거나 줄일 수 있습니다.
- **선언적 구성**: 원하는 상태(desired state)를 YAML 파일 등으로 정의하면, 쿠버네티스가 현재 상태를 그에 맞게 자동으로 유지합니다.

---

## 2. 쿠버네티스 핵심 개념

쿠버네티스를 이해하기 위해 알아야 할 몇 가지 핵심 객체(Object)들이 있습니다.

- **클러스터 (Cluster)**: 쿠버네티스가 설치된 전체 서버 그룹입니다. 최소 하나 이상의 마스터 노드와 여러 개의 워커 노드로 구성됩니다.
- **노드 (Node)**: 클러스터 내의 개별 서버(가상 머신 또는 물리 서버)입니다. 애플리케이션 컨테이너가 실제로 실행되는 공간입니다.
- **파드 (Pod)**: 쿠버네티스에서 생성하고 관리할 수 있는 가장 작은 배포 단위입니다. 하나 이상의 컨테이너와 스토리지, 네트워크 속성을 공유하는 그룹입니다. 일반적으로 파드 하나에 컨테이너 하나를 실행합니다.
- **서비스 (Service)**: 여러 파드를 논리적인 하나의 그룹으로 묶고, 이 그룹에 접근할 수 있는 고유한 주소(IP 또는 DNS)를 제공합니다. 외부에서 파드에 접근하거나 파드 간에 통신할 때 사용됩니다.
- **디플로이먼트 (Deployment)**: 파드와 레플리카셋(ReplicaSet)을 관리하는 객체입니다. 애플리케이션의 배포, 업데이트, 확장 및 롤백을 담당합니다.
- **네임스페이스 (Namespace)**: 하나의 클러스터 내에서 리소스를 논리적으로 격리하는 가상 클러스터입니다. 개발, 테스트, 운영 환경을 분리하는 등의 용도로 사용됩니다.
- **컨피그맵 (ConfigMap) & 시크릿 (Secret)**: 애플리케이션의 설정값이나 비밀번호, API 키 등 민감한 정보를 코드와 분리하여 관리하기 위한 객체입니다.

---

## 3. 쿠버네티스 아키텍처

쿠버네티스 클러스터는 크게 **컨트롤 플레인(Control Plane)**과 **워커 노드(Worker Node)**로 나뉩니다.

### 컨트롤 플레인 (마스터 노드)
클러스터 전체를 관리하고 조율하는 두뇌 역할을 합니다. 주요 구성 요소는 다음과 같습니다.
- **kube-apiserver**: 쿠버네티스 API를 노출하는 프론트엔드입니다. `kubectl`과 같은 도구가 클러스터와 상호작용하는 통로입니다.
- **etcd**: 모든 클러스터 데이터를 저장하는 키-값 저장소입니다. 클러스터의 상태 정보, 설정 등을 보관합니다.
- **kube-scheduler**: 새로 생성된 파드를 어느 워커 노드에 할당할지 결정합니다.
- **kube-controller-manager**: 파드, 디플로이먼트 등 각종 리소스를 관리하는 컨트롤러들을 실행합니다.

### 워커 노드
실제 애플리케이션 컨테이너가 실행되는 곳입니다.
- **kubelet**: 각 노드에서 실행되는 에이전트로, 컨트롤 플레인과 통신하며 파드 내 컨테이너의 실행을 관리합니다.
- **kube-proxy**: 노드의 네트워크 규칙을 관리하고, 서비스(Service)를 통해 외부 또는 내부에서 파드로 들어오는 네트워크 트래픽을 전달합니다.
- **컨테이너 런타임 (Container Runtime)**: 도커(Docker), containerd 등 실제로 컨테이너를 실행하는 소프트웨어입니다.

---

## 4. 기본 구성 파일 (YAML) 예제

쿠버네티스에서는 주로 YAML 형식의 파일을 사용하여 리소스를 정의하고 배포합니다. 다음은 간단한 Nginx 웹서버를 배포하는 예제입니다.

### 1. Deployment 예제 (`nginx-deployment.yaml`)
3개의 Nginx 파드를 실행하도록 정의하는 디플로이먼트입니다.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deployment
spec:
  replicas: 3 # 3개의 파드를 실행
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - name: nginx
        image: nginx:1.25.3 # 사용할 컨테이너 이미지
        ports:
        - containerPort: 80 # 컨테이너가 노출할 포트
```

### 2. Service 예제 (`nginx-service.yaml`)
위에서 생성한 Nginx 파드들을 외부에서 접근할 수 있도록 `LoadBalancer` 타입의 서비스로 노출합니다.

```yaml
apiVersion: v1
kind: Service
metadata:
  name: nginx-service
spec:
  selector:
    app: nginx # 'app: nginx' 레이블을 가진 파드를 대상으로 함
  ports:
    - protocol: TCP
      port: 80       # 서비스가 노출할 포트
      targetPort: 80 # 파드의 컨테이너가 노출하는 포트
  type: LoadBalancer # 외부에서 접근 가능한 IP를 할당받는 타입
```

### 사용 방법
`kubectl`이라는 커맨드라인 도구를 사용하여 위 YAML 파일들을 클러스터에 적용할 수 있습니다.

```bash
# 1. 디플로이먼트 생성
kubectl apply -f nginx-deployment.yaml

# 2. 서비스 생성
kubectl apply -f nginx-service.yaml

# 3. 생성된 파드 및 서비스 확인
kubectl get pods
kubectl get services
```

---

## 5. Docker Compose에서 쿠버네티스로 마이그레이션

이미 `docker-compose.yml`로 관리되는 프로젝트가 있다면, 이를 쿠버네티스 환경으로 이전할 수 있습니다. 쿠버네티스는 더 향상된 안정성과 확장성을 제공합니다.

### 왜 쿠버네티스를 사용하는가?
- **자동 복구 (Self-healing):** 컨테이너에 문제가 생기면 쿠버네티스가 자동으로 재시작하여 서비스 중단을 최소화합니다.
- **오토 스케일링 (Auto-scaling):** 트래픽 변화에 따라 자동으로 컨테이너 수를 조절하여 리소스를 효율적으로 사용합니다.
- **무중단 업데이트:** 서비스 중단 없이 새로운 버전의 애플리케이션을 배포할 수 있습니다.

### Docker Compose와 쿠버네티스 개념 매핑

| Docker Compose (`docker-compose.yml`) | 쿠버네티스 동등 객체 (YAML) | 설명 |
| :--- | :--- | :--- |
| `services` (e.g., `nginx`, `php`, `db`) | `Deployment` 또는 `StatefulSet` | 애플리케이션의 배포를 정의하고, 실행할 컨테이너(Pod) 수를 관리합니다. (DB는 `StatefulSet`) |
| `image` | `Deployment` 내의 `spec.template.spec.containers.image` | 실행할 도커 이미지 주소를 지정합니다. |
| `ports` | `Service` | 외부에서 웹 서버에 접근할 수 있도록 포트를 노출하고, 여러 컨테이너에 트래픽을 분산합니다. |
| `volumes` | `PersistentVolume` (PV) & `PersistentVolumeClaim` (PVC) | 데이터베이스 파일이나 사용자 업로드 파일처럼 영구적으로 보존되어야 할 데이터를 저장합니다. |
| `networks` | `Service`와 쿠버네티스 내부 DNS | 쿠버네티스는 서비스 이름을 통해 컨테이너 간 통신을 자동으로 처리합니다. (e.g., `php`가 `db`에 `mysql-service`라는 이름으로 접근) |
| `environment` / `secrets` | `ConfigMap` & `Secret` | DB 접속 정보나 비밀번호 등 민감한 설정 정보를 안전하게 관리합니다. |
| `build` | (별도 과정) | 쿠버네티스는 이미 빌드된 이미지를 레지스트리(e.g., Docker Hub)에서 가져옵니다. `docker build` -> `docker push` 과정이 선행되어야 합니다. |

### 마이그레이션 절차 요약

1.  **컨테이너 이미지 빌드 및 푸시:** `Dockerfile`을 사용하여 애플리케이션 이미지를 빌드하고, Docker Hub와 같은 컨테이너 레지스트리에 푸시합니다.
2.  **쿠버네티스 YAML 파일 작성:**
    *   **데이터베이스 (e.g., MySQL):** 데이터 영속성을 위해 `StatefulSet`과 `PersistentVolumeClaim`을 정의합니다. DB 접속 정보는 `Secret`으로 관리합니다.
    *   **애플리케이션 (e.g., PHP-FPM):** `Deployment`를 사용하여 배포합니다.
    *   **웹 서버 (e.g., Nginx):** `Deployment`를 사용하여 배포하고, `ConfigMap`을 사용하여 설정 파일을 주입합니다.
    *   **네트워킹:** 각 `Deployment`나 `StatefulSet`을 연결하고 외부로 노출시키기 위한 `Service` 객체들을 정의합니다.
3.  **쿠버네티스 클러스터에 배포:** `kubectl apply -f <yaml_파일_경로>` 명령어로 작성된 파일들을 클러스터에 적용합니다.