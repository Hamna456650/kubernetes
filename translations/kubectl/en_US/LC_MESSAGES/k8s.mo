��    I      d  a   �      0  �   1  �   �  �     y  C  s   �	  �  1
  ]  �  �    q   �  �   ;  �   �  i   �  [   A  G  �  a   �  a   G  ;   �  U   �  �   ;  9   �  3   �  �   -  �     �   �  7  �  /  �  Q  '  /   y  �   �  �   m  �   U  W     W   _  m   �  �   %  M   	   G   W   A   �   =   �   E   !  E   e!  ?   �!  [   �!  [   G"  3   �"  G   �"    #  )  %$  �   O%  M   �%  �   /&  �   �&  �   �'  �  �(  �   S*  �   +  �   �+  �   S,  �  A-  �  �.  =  y0  9   �2  �   �2  _   �3  =   �3  {   94  I   �4  W   �4  �   W5  %   =6  1   c6  (  �6  �  �7  [   k9  J   �9  a   :  �   t:  9   1;  �   k;  �   1<  �   �<  8   �=  W   �=  u   H>  4   �>  -   �>  �   !?  0   �?  0   �?     '@  *   E@  A   p@     �@     �@  v   �@  p   `A  `   �A  �   2B  �   �B  �   fC     D  a   'D  s   �D  X   �D  +   VE  +   �E  6   �E  q   �E  &   WF  #   ~F      �F     �F  "   �F  "   G     (G  -   HG  -   vG     �G  #   �G  �   �G  �   eH  H   �H  &   CI  e   jI  z   �I  J   KJ  �   �J  W   |K  E   �K  a   L  v   |L  �   �L  �   �M    �N     �O  T   �O  /    P     PP  =   oP  $   �P  +   �P  r   �P     qQ     �Q  �   �Q     &             6      -       
   C      H      )       3                     :       G            8          F   %   @                 >   4      7   0   B          "   ?       +   *       ,   I       ;   2       =   '                          .   9   !   $   A         /   E   1   5           	               <         D                 (             #    A comma-delimited set of quota scopes that must all match each object tracked by the quota.A comma-delimited set of quota scopes that must all match each object tracked by the quota. A comma-delimited set of resource=quantity pairs that define a hard limit.A comma-delimited set of resource=quantity pairs that define a hard limit. A label selector to use for this budget. Only equality-based selector requirements are supported.A label selector to use for this budget. Only equality-based selector requirements are supported. A label selector to use for this service. Only equality-based selector requirements are supported. If empty (the default) infer the selector from the replication controller or replica set.A label selector to use for this service. Only equality-based selector requirements are supported. If empty (the default) infer the selector from the replication controller or replica set. A schedule in the Cron format the job should be run with.A schedule in the Cron format the job should be run with. Additional external IP address (not managed by Kubernetes) to accept for the service. If this IP is routed to a node, the service can be accessed by this IP in addition to its generated service IP.Additional external IP address (not managed by Kubernetes) to accept for the service. If this IP is routed to a node, the service can be accessed by this IP in addition to its generated service IP. An inline JSON override for the generated object. If this is non-empty, it is used to override the generated object. Requires that the object supply a valid apiVersion field.An inline JSON override for the generated object. If this is non-empty, it is used to override the generated object. Requires that the object supply a valid apiVersion field. An inline JSON override for the generated service object. If this is non-empty, it is used to override the generated object. Requires that the object supply a valid apiVersion field.  Only used if --expose is true.An inline JSON override for the generated service object. If this is non-empty, it is used to override the generated object. Requires that the object supply a valid apiVersion field.  Only used if --expose is true. Apply a configuration to a resource by filename or stdinApply a configuration to a resource by filename or stdin Assign your own ClusterIP or set to 'None' for a 'headless' service (no loadbalancing).Assign your own ClusterIP or set to 'None' for a 'headless' service (no loadbalancing). ClusterIP to be assigned to the service. Leave empty to auto-allocate, or set to 'None' to create a headless service.ClusterIP to be assigned to the service. Leave empty to auto-allocate, or set to 'None' to create a headless service. ClusterRole this ClusterRoleBinding should referenceClusterRole this ClusterRoleBinding should reference ClusterRole this RoleBinding should referenceClusterRole this RoleBinding should reference Container name which will have its image upgraded. Only relevant when --image is specified, ignored otherwise. Required when using --image on a multi-container podContainer name which will have its image upgraded. Only relevant when --image is specified, ignored otherwise. Required when using --image on a multi-container pod Delete the specified cluster from the kubeconfigDelete the specified cluster from the kubeconfig Delete the specified context from the kubeconfigDelete the specified context from the kubeconfig Describe one or many contextsDescribe one or many contexts Display clusters defined in the kubeconfigDisplay clusters defined in the kubeconfig Display merged kubeconfig settings or a specified kubeconfig fileDisplay merged kubeconfig settings or a specified kubeconfig file Displays the current-contextDisplays the current-context Email for Docker registryEmail for Docker registry Explicit policy for when to pull container images. Required when --image is same as existing image, ignored otherwise.Explicit policy for when to pull container images. Required when --image is same as existing image, ignored otherwise. IP to assign to the Load Balancer. If empty, an ephemeral IP will be created and used (cloud-provider specific).IP to assign to the Load Balancer. If empty, an ephemeral IP will be created and used (cloud-provider specific). If non-empty, set the session affinity for the service to this; legal values: 'None', 'ClientIP'If non-empty, set the session affinity for the service to this; legal values: 'None', 'ClientIP' If non-empty, the annotation update will only succeed if this is the current resource-version for the object. Only valid when specifying a single resource.If non-empty, the annotation update will only succeed if this is the current resource-version for the object. Only valid when specifying a single resource. If non-empty, the labels update will only succeed if this is the current resource-version for the object. Only valid when specifying a single resource.If non-empty, the labels update will only succeed if this is the current resource-version for the object. Only valid when specifying a single resource. Image to use for upgrading the replication controller. Must be distinct from the existing image (either new image or new image tag).  Can not be used with --filename/-fImage to use for upgrading the replication controller. Must be distinct from the existing image (either new image or new image tag).  Can not be used with --filename/-f Modify kubeconfig filesModify kubeconfig files Name or number for the port on the container that the service should direct traffic to. Optional.Name or number for the port on the container that the service should direct traffic to. Optional. Only return logs after a specific date (RFC3339). Defaults to all logs. Only one of since-time / since may be used.Only return logs after a specific date (RFC3339). Defaults to all logs. Only one of since-time / since may be used. Output the formatted object with the given group version (for ex: 'extensions/v1beta1').Output the formatted object with the given group version (for ex: 'extensions/v1beta1'). Password for Docker registry authenticationPassword for Docker registry authentication Path to PEM encoded public key certificate.Path to PEM encoded public key certificate. Path to private key associated with given certificate.Path to private key associated with given certificate. Precondition for resource version. Requires that the current resource version match this value in order to scale.Precondition for resource version. Requires that the current resource version match this value in order to scale. Role this RoleBinding should referenceRole this RoleBinding should reference Server location for Docker registryServer location for Docker registry Set specific features on objectsSet specific features on objects Set the selector on a resourceSet the selector on a resource Sets a cluster entry in kubeconfigSets a cluster entry in kubeconfig Sets a context entry in kubeconfigSets a context entry in kubeconfig Sets a user entry in kubeconfigSets a user entry in kubeconfig Sets an individual value in a kubeconfig fileSets an individual value in a kubeconfig file Sets the current-context in a kubeconfig fileSets the current-context in a kubeconfig file Synonym for --target-portSynonym for --target-port The image for the container to run.The image for the container to run. The image pull policy for the container. If left empty, this value will not be specified by the client and defaulted by the serverThe image pull policy for the container. If left empty, this value will not be specified by the client and defaulted by the server The key to use to differentiate between two different controllers, default 'deployment'.  Only relevant when --image is specified, ignored otherwiseThe key to use to differentiate between two different controllers, default 'deployment'.  Only relevant when --image is specified, ignored otherwise The minimum number or percentage of available pods this budget requires.The minimum number or percentage of available pods this budget requires. The name for the newly created object.The name for the newly created object. The name for the newly created object. If not specified, the name of the input resource will be used.The name for the newly created object. If not specified, the name of the input resource will be used. The name of the API generator to use, see http://kubernetes.io/docs/user-guide/kubectl-conventions/#generators for a list.The name of the API generator to use, see http://kubernetes.io/docs/user-guide/kubectl-conventions/#generators for a list. The name of the API generator to use. Currently there is only 1 generator.The name of the API generator to use. Currently there is only 1 generator. The name of the API generator to use. There are 2 generators: 'service/v1' and 'service/v2'. The only difference between them is that service port in v1 is named 'default', while it is left unnamed in v2. Default is 'service/v2'.The name of the API generator to use. There are 2 generators: 'service/v1' and 'service/v2'. The only difference between them is that service port in v1 is named 'default', while it is left unnamed in v2. Default is 'service/v2'. The name of the generator to use for creating a service.  Only used if --expose is trueThe name of the generator to use for creating a service.  Only used if --expose is true The network protocol for the service to be created. Default is 'TCP'.The network protocol for the service to be created. Default is 'TCP'. The port that the service should serve on. Copied from the resource being exposed, if unspecifiedThe port that the service should serve on. Copied from the resource being exposed, if unspecified The port that this container exposes.  If --expose is true, this is also the port used by the service that is created.The port that this container exposes.  If --expose is true, this is also the port used by the service that is created. The resource requirement limits for this container.  For example, 'cpu=200m,memory=512Mi'.  Note that server side components may assign limits depending on the server configuration, such as limit ranges.The resource requirement limits for this container.  For example, 'cpu=200m,memory=512Mi'.  Note that server side components may assign limits depending on the server configuration, such as limit ranges. The resource requirement requests for this container.  For example, 'cpu=100m,memory=256Mi'.  Note that server side components may assign requests depending on the server configuration, such as limit ranges.The resource requirement requests for this container.  For example, 'cpu=100m,memory=256Mi'.  Note that server side components may assign requests depending on the server configuration, such as limit ranges. The restart policy for this Pod.  Legal values [Always, OnFailure, Never].  If set to 'Always' a deployment is created, if set to 'OnFailure' a job is created, if set to 'Never', a regular pod is created. For the latter two --replicas must be 1.  Default 'Always', for CronJobs `Never`.The restart policy for this Pod.  Legal values [Always, OnFailure, Never].  If set to 'Always' a deployment is created, if set to 'OnFailure' a job is created, if set to 'Never', a regular pod is created. For the latter two --replicas must be 1.  Default 'Always', for CronJobs `Never`. The type of secret to createThe type of secret to create Type for this service: ClusterIP, NodePort, or LoadBalancer. Default is 'ClusterIP'.Type for this service: ClusterIP, NodePort, or LoadBalancer. Default is 'ClusterIP'. Unsets an individual value in a kubeconfig fileUnsets an individual value in a kubeconfig file Update image of a pod templateUpdate image of a pod template Update resource requests/limits on objects with pod templatesUpdate resource requests/limits on objects with pod templates Update the annotations on a resourceUpdate the annotations on a resource Username for Docker registry authenticationUsername for Docker registry authentication Where to output the files.  If empty or '-' uses stdout, otherwise creates a directory hierarchy in that directoryWhere to output the files.  If empty or '-' uses stdout, otherwise creates a directory hierarchy in that directory dummy restart flagdummy restart flag external name of serviceexternal name of service watch is only supported on individual resources and resource collections - %d resources were foundwatch is only supported on individual resources and resource collections - %d resources were found watch is only supported on individual resources and resource collections - %d resources were found Project-Id-Version: gettext-go-examples-hello
Report-Msgid-Bugs-To: 
POT-Creation-Date: 2013-12-12 20:03+0000
PO-Revision-Date: 2017-01-29 14:45-0800
Last-Translator: Brendan Burns <brendan.d.burns@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit
X-Generator: Poedit 1.6.10
X-Poedit-SourceCharset: UTF-8
Language-Team: 
Plural-Forms: nplurals=2; plural=(n != 1);
Language: en
 A comma-delimited set of quota scopes that must all match each object tracked by the quota. A comma-delimited set of resource=quantity pairs that define a hard limit. A label selector to use for this budget. Only equality-based selector requirements are supported. A label selector to use for this service. Only equality-based selector requirements are supported. If empty (the default) infer the selector from the replication controller or replica set. A schedule in the Cron format the job should be run with. Additional external IP address (not managed by Kubernetes) to accept for the service. If this IP is routed to a node, the service can be accessed by this IP in addition to its generated service IP. An inline JSON override for the generated object. If this is non-empty, it is used to override the generated object. Requires that the object supply a valid apiVersion field. An inline JSON override for the generated service object. If this is non-empty, it is used to override the generated object. Requires that the object supply a valid apiVersion field.  Only used if --expose is true. Apply a configuration to a resource by filename or stdin Assign your own ClusterIP or set to 'None' for a 'headless' service (no loadbalancing). ClusterIP to be assigned to the service. Leave empty to auto-allocate, or set to 'None' to create a headless service. ClusterRole this ClusterRoleBinding should reference ClusterRole this RoleBinding should reference Container name which will have its image upgraded. Only relevant when --image is specified, ignored otherwise. Required when using --image on a multi-container pod Delete the specified cluster from the kubeconfig Delete the specified context from the kubeconfig Describe one or many contexts Display clusters defined in the kubeconfig Display merged kubeconfig settings or a specified kubeconfig file Displays the current-context Email for Docker registry Explicit policy for when to pull container images. Required when --image is same as existing image, ignored otherwise. IP to assign to the Load Balancer. If empty, an ephemeral IP will be created and used (cloud-provider specific). If non-empty, set the session affinity for the service to this; legal values: 'None', 'ClientIP' If non-empty, the annotation update will only succeed if this is the current resource-version for the object. Only valid when specifying a single resource. If non-empty, the labels update will only succeed if this is the current resource-version for the object. Only valid when specifying a single resource. Image to use for upgrading the replication controller. Must be distinct from the existing image (either new image or new image tag).  Can not be used with --filename/-f Modify kubeconfig files Name or number for the port on the container that the service should direct traffic to. Optional. Only return logs after a specific date (RFC3339). Defaults to all logs. Only one of since-time / since may be used. Output the formatted object with the given group version (for ex: 'extensions/v1beta1'). Password for Docker registry authentication Path to PEM encoded public key certificate. Path to private key associated with given certificate. Precondition for resource version. Requires that the current resource version match this value in order to scale. Role this RoleBinding should reference Server location for Docker registry Set specific features on objects Set the selector on a resource Sets a cluster entry in kubeconfig Sets a context entry in kubeconfig Sets a user entry in kubeconfig Sets an individual value in a kubeconfig file Sets the current-context in a kubeconfig file Synonym for --target-port The image for the container to run. The image pull policy for the container. If left empty, this value will not be specified by the client and defaulted by the server The key to use to differentiate between two different controllers, default 'deployment'.  Only relevant when --image is specified, ignored otherwise The minimum number or percentage of available pods this budget requires. The name for the newly created object. The name for the newly created object. If not specified, the name of the input resource will be used. The name of the API generator to use, see http://kubernetes.io/docs/user-guide/kubectl-conventions/#generators for a list. The name of the API generator to use. Currently there is only 1 generator. The name of the API generator to use. There are 2 generators: 'service/v1' and 'service/v2'. The only difference between them is that service port in v1 is named 'default', while it is left unnamed in v2. Default is 'service/v2'. The name of the generator to use for creating a service.  Only used if --expose is true The network protocol for the service to be created. Default is 'TCP'. The port that the service should serve on. Copied from the resource being exposed, if unspecified The port that this container exposes.  If --expose is true, this is also the port used by the service that is created. The resource requirement limits for this container.  For example, 'cpu=200m,memory=512Mi'.  Note that server side components may assign limits depending on the server configuration, such as limit ranges. The resource requirement requests for this container.  For example, 'cpu=100m,memory=256Mi'.  Note that server side components may assign requests depending on the server configuration, such as limit ranges. The restart policy for this Pod.  Legal values [Always, OnFailure, Never].  If set to 'Always' a deployment is created, if set to 'OnFailure' a job is created, if set to 'Never', a regular pod is created. For the latter two --replicas must be 1.  Default 'Always', for CronJobs `Never`. The type of secret to create Type for this service: ClusterIP, NodePort, or LoadBalancer. Default is 'ClusterIP'. Unsets an individual value in a kubeconfig file Update image of a pod template Update resource requests/limits on objects with pod templates Update the annotations on a resource Username for Docker registry authentication Where to output the files.  If empty or '-' uses stdout, otherwise creates a directory hierarchy in that directory dummy restart flag external name of service watch is only supported on individual resources and resource collections - %d resource was found watch is only supported on individual resources and resource collections - %d resources were found 