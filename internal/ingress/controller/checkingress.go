/*
Copyright 2022 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"fmt"
	"strings"
	"time"

	networking "k8s.io/api/networking/v1"
	"k8s.io/ingress-nginx/internal/ingress/annotations"
	"k8s.io/ingress-nginx/internal/ingress/annotations/parser"
	"k8s.io/ingress-nginx/internal/ingress/controller/store"
	"k8s.io/ingress-nginx/internal/ingress/inspector"
	"k8s.io/ingress-nginx/internal/k8s"
	"k8s.io/ingress-nginx/pkg/apis/ingress"
	"k8s.io/klog/v2"
)

// CheckIngress returns an error in case the provided ingress, when added
// to the current configuration, generates an invalid configuration
func (n *NGINXController) CheckIngress(ing *networking.Ingress) error {
	startCheck := time.Now().UnixNano() / 1000000

	if ing == nil {
		// no ingress to add, no state change
		return nil
	}

	// Skip checks if the ingress is marked as deleted
	if !ing.DeletionTimestamp.IsZero() {
		return nil
	}
	if n.cfg.DeepInspector {
		if err := inspector.DeepInspect(ing); err != nil {
			return fmt.Errorf("invalid object: %w", err)
		}
	}
	// Do not attempt to validate an ingress that's not meant to be controlled by the current instance of the controller.
	if ingressClass, err := n.store.GetIngressClass(ing, n.cfg.IngressClassConfiguration); ingressClass == "" {
		klog.Warningf("ignoring ingress %v in %v based on annotation %v: %v", ing.Name, ing.ObjectMeta.Namespace, ingressClass, err)
		return nil
	}

	if n.cfg.Namespace != "" && ing.ObjectMeta.Namespace != n.cfg.Namespace {
		klog.Warningf("ignoring ingress %v in namespace %v different from the namespace watched %s", ing.Name, ing.ObjectMeta.Namespace, n.cfg.Namespace)
		return nil
	}

	if n.cfg.DisableCatchAll && ing.Spec.DefaultBackend != nil {
		return fmt.Errorf("this deployment is trying to create a catch-all ingress while DisableCatchAll flag is set to true. Remove '.spec.backend' or set DisableCatchAll flag to false")
	}
	startRender := time.Now().UnixNano() / 1000000
	cfg := n.store.GetBackendConfiguration()
	cfg.Resolver = n.resolver

	var arrayBadWords []string

	if cfg.AnnotationValueWordBlocklist != "" {
		arrayBadWords = strings.Split(strings.TrimSpace(cfg.AnnotationValueWordBlocklist), ",")
	}

	for key, value := range ing.ObjectMeta.GetAnnotations() {

		if parser.AnnotationsPrefix != parser.DefaultAnnotationsPrefix {
			if strings.HasPrefix(key, fmt.Sprintf("%s/", parser.DefaultAnnotationsPrefix)) {
				return fmt.Errorf("this deployment has a custom annotation prefix defined. Use '%s' instead of '%s'", parser.AnnotationsPrefix, parser.DefaultAnnotationsPrefix)
			}
		}

		if strings.HasPrefix(key, fmt.Sprintf("%s/", parser.AnnotationsPrefix)) && len(arrayBadWords) != 0 {
			for _, forbiddenvalue := range arrayBadWords {
				if strings.Contains(value, strings.TrimSpace(forbiddenvalue)) {
					return fmt.Errorf("%s annotation contains invalid word %s", key, forbiddenvalue)
				}
			}
		}

		if !cfg.AllowSnippetAnnotations && strings.HasSuffix(key, "-snippet") {
			return fmt.Errorf("%s annotation cannot be used. Snippet directives are disabled by the Ingress administrator", key)
		}

		if len(cfg.GlobalRateLimitMemcachedHost) == 0 && strings.HasPrefix(key, fmt.Sprintf("%s/%s", parser.AnnotationsPrefix, "global-rate-limit")) {
			return fmt.Errorf("'global-rate-limit*' annotations require 'global-rate-limit-memcached-host' settings configured in the global configmap")
		}

	}

	k8s.SetDefaultNGINXPathType(ing)

	allIngresses := n.store.ListIngresses()

	filter := func(toCheck *ingress.Ingress) bool {
		return toCheck.ObjectMeta.Namespace == ing.ObjectMeta.Namespace &&
			toCheck.ObjectMeta.Name == ing.ObjectMeta.Name
	}
	ings := store.FilterIngresses(allIngresses, filter)
	ings = append(ings, &ingress.Ingress{
		Ingress:           *ing,
		ParsedAnnotations: annotations.NewAnnotationExtractor(n.store).Extract(ing),
	})
	startTest := time.Now().UnixNano() / 1000000
	//_, servers, pcfg := n.getConfiguration(ings)
	_, servers, _ := n.getConfiguration(ings) // TODO: Fix when we get the right configuration and pass to template tester

	err := checkOverlap(ing, allIngresses, servers)
	if err != nil {
		n.metricCollector.IncCheckErrorCount(ing.ObjectMeta.Namespace, ing.Name)
		return err
	}
	testedSize := len(ings)
	if n.cfg.DisableFullValidationTest {
		// _, _, pcfg = n.getConfiguration(ings[len(ings)-1:]) // TODO: uncomment as soon as we get the right webhook working

		testedSize = 1
	}

	/* TODO: THIS FIX SHOULD HAPPEN! We need to figure out a sidecar container that just receives a request to test and returns the error (maybe another gRPC endpoint)
	content, err := n.generateTemplate(cfg, *pcfg)
	if err != nil {
		n.metricCollector.IncCheckErrorCount(ing.ObjectMeta.Namespace, ing.Name)
		return err
	}

	err = n.testTemplate(content)
	if err != nil {
		n.metricCollector.IncCheckErrorCount(ing.ObjectMeta.Namespace, ing.Name)
		return err
	}*/
	n.metricCollector.IncCheckCount(ing.ObjectMeta.Namespace, ing.Name)
	endCheck := time.Now().UnixNano() / 1000000
	n.metricCollector.SetAdmissionMetrics(
		float64(testedSize),
		float64(endCheck-startTest)/1000,
		float64(len(ings)),
		float64(startTest-startRender)/1000,
		0, // TODO: Remove
		//float64(len(content)), // TODO: READ as soon as we re-enable the webhook check correctly
		float64(endCheck-startCheck)/1000,
	)
	return nil
}
