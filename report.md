# Dependency Confusion Scan — Report

Generated: 2026-06-19T03:33:21.296Z

> Detection only. Findings are candidates for **responsible disclosure / bug bounty**. No packages were published.

## Summary

- Domains processed: **8195**
- Domains with a matched public org/repos: **2910**
- Total dependency names inspected: **141219**
- **Domains with VULNERABLE packages: 57**
- Domains with only low-risk (scope-owned) notes: 58

## ⚠️ Vulnerable (unclaimed packages — confusable)

| Company | Unclaimed package(s) | Type | Source (repo/file) |
|---|---|---|---|
| microsoft.com | `@msdyn365-commerce-modules/starter-pack` | scoped pkg | `github:microsoft/Msdyn365.Commerce.Online/master/package.json` |
| microsoft.com | `@msdyn365-commerce-modules/fabrikam-design-kit` | scoped pkg | `github:microsoft/Msdyn365.Commerce.Online/master/package.json` |
| microsoft.com | `@msdyn365-commerce/bootloader` | scoped pkg | `github:microsoft/Msdyn365.Commerce.Online/master/package.json` |
| microsoft.com | `@msdyn365-commerce/retail-proxy` | scoped pkg | `github:microsoft/Msdyn365.Commerce.Online/master/package.json` |
| microsoft.com | `@msdyn365-commerce-modules/msdyn365-exp-test-connector` | scoped pkg | `github:microsoft/Msdyn365.Commerce.Online/master/package.json` |
| microsoft.com | `@msdyn365-commerce-theme/adventureworks-theme-kit` | scoped pkg | `github:microsoft/Msdyn365.Commerce.Online/master/package.json` |
| microsoft.com | `@msdyn365-commerce/eslint-config` | scoped pkg | `github:microsoft/Msdyn365.Commerce.Online/master/package.json` |
| microsoft.com | `@msdyn365-commerce-theme` | scope decl (.npmrc) | `github:microsoft/Msdyn365.Commerce.Online/master/.npmrc` |
| microsoft.com | `@msdyn365-commerce-modules` | scope decl (.npmrc) | `github:microsoft/Msdyn365.Commerce.Online/master/.npmrc` |
| microsoft.com | `@msdyn365-commerce` | scope decl (.npmrc) | `github:microsoft/Msdyn365.Commerce.Online/master/.npmrc` |
| goodybag.com | `@goodybag/cater-web` | scoped pkg | `github:goodybag/cater-api-server/master/package.json` |
| goodybag.com | `@goodybag/dropoff-client` | scoped pkg | `github:goodybag/cater-api-server/master/package.json` |
| goodybag.com | `@goodybag/order-status-worker` | scoped pkg | `github:goodybag/cater-api-server/master/package.json` |
| goodybag.com | `@goodybag/scheduler-app` | scoped pkg | `github:goodybag/cater-api-server/master/package.json` |
| goodybag.com | `@goodybag/models-order` | scoped pkg | `github:goodybag/cater-web/master/package.json` |
| goodybag.com | `@goodybag/react-pickadate` | scoped pkg | `github:goodybag/cater-web/master/package.json` |
| goodybag.com | `diet-tags` | bare pkg | `github:goodybag/cater-web/master/package.json` |
| goodybag.com | `font-avenir` | bare pkg | `github:goodybag/lunchroom-landing/master/package.json` |
| goodybag.com | `gb-icon-font` | bare pkg | `github:goodybag/lunchroom-landing/master/package.json` |
| siemens.com | `@siemens-ux/design-tokens` | scoped pkg | `github:siemens/element/main/package.json` |
| siemens.com | `@simpl/brand` | scoped pkg | `github:siemens/element/main/package.json` |
| siemens.com | `@simpl/docs-composer` | scoped pkg | `github:siemens/element/main/package.json` |
| siemens.com | `@simpl` | scope decl (.npmrc) | `github:siemens/element/main/.npmrc` |
| siemens.com | `@simpl-labs` | scope decl (.npmrc) | `github:siemens/element/main/.npmrc` |
| siemens.com | `@siemens-ux` | scope decl (.npmrc) | `github:siemens/element/main/.npmrc` |
| tispr.com | `@tispr/loopback-datasource-juggler` | scoped pkg | `github:tispr/loopback-connector-mongodb/master/package.json` |
| tispr.com | `@tispr` | scope decl (.npmrc) | `github:tispr/loopback-connector-mongodb/master/.npmrc` |
| tispr.com | `@tispr/loopback` | scoped pkg | `github:tispr/loopback-component-push/master/package.json` |
| tispr.com | `@tispr/loopback-connector-mongodb` | scoped pkg | `github:tispr/loopback-component-push/master/package.json` |
| tispr.com | `@tispr/strong-remoting` | scoped pkg | `github:tispr/loopback-connector-remote/master/package.json` |
| tispr.com | `@tispr/loopback-connector-remote` | scoped pkg | `github:tispr/loopback/master/package.json` |
| waldophotos.com | `@waldo/kafking` | scoped pkg | `github:waldophotos/node-kaf/master/package.json` |
| waldophotos.com | `@waldo/kafka-to-sqs` | scoped pkg | `github:waldophotos/node-fetcher/master/package.json` |
| waldophotos.com | `@waldo/node-kafka` | scoped pkg | `github:waldophotos/node-fetcher/master/package.json` |
| waldophotos.com | `@waldo/sqs` | scoped pkg | `github:waldophotos/node-fetcher/master/package.json` |
| waldophotos.com | `@waldo/node-kafka-stub` | scoped pkg | `github:waldophotos/node-fetcher/master/package.json` |
| monaverse.com | `com.monaverse.coresdk` | bare pkg | `github:monaverse/MonaBrainsSDK/main/package.json` |
| monaverse.com | `com.vrmc.vrm` | bare pkg | `github:monaverse/MonaBrainsSDK/main/package.json` |
| monaverse.com | `com.monaverse.unitygltf` | bare pkg | `github:monaverse/MonaBrainsSDK/main/package.json` |
| monaverse.com | `com.monaverse.brainssdk` | bare pkg | `github:monaverse/MonaUnityGLTF/main/package.json` |
| loop.baby | `@fern-fern/generator-exec-sdk` | scoped pkg | `github:loop/fern/main/package.json` |
| loop.baby | `@fern-fern/ir-v39-sdk` | scoped pkg | `github:loop/fern/main/package.json` |
| loop.baby | `@fern-fern` | scope decl (.npmrc) | `github:loop/fern/main/.npmrc` |
| anaconda.com | `@anaconda/playwright-utils` | scoped pkg | `github:anaconda/anaconda-ai/main/package.json` |
| anaconda.com | `@anaconda` | scope decl (.npmrc) | `github:anaconda/anaconda-ai/main/.npmrc` |
| digicert.com | `@digicert/ssm-client-tools-installer` | scoped pkg | `github:digicert/ssm-code-signing/master/package.json` |
| digicert.com | `@digicert` | scope decl (.npmrc) | `github:digicert/ssm-code-signing/master/.npmrc` |
| lookback.io | `@lookback/lookbook` | scoped pkg | `github:lookback/lookbook-website/main/package.json` |
| lookback.io | `eslint-config-lookback` | bare pkg | `github:lookback/meteor-emails/master/package.json` |
| nodeshift.com | `@redhat/opossum` | scoped pkg | `github:nodeshift/npm_install_scheduler/main/package.json` |
| nodeshift.com | `@redhat` | scope decl (.npmrc) | `github:nodeshift/npm_install_scheduler/main/.npmrc` |
| shippabo.com | `@app/frontend` | scoped pkg | `github:shippabo/shippabo-retrospective/main/package.json` |
| shippabo.com | `@app/server` | scoped pkg | `github:shippabo/shippabo-retrospective/main/package.json` |
| snovio.awsapps.com | `@metronome-sh/express` | scoped pkg | `github:awsapps/kentcdodds.com/main/package.json` |
| snovio.awsapps.com | `@metronome-sh/react` | scoped pkg | `github:awsapps/kentcdodds.com/main/package.json` |
| adaptive.live | `@adaptive` | scope decl (.npmrc) | `github:adaptive/makeid/master/.npmrc` |
| airwallex.com | `@gtpn` | scope decl (.npmrc) | `github:airwallex/payouts-web-sdk/master/.npmrc` |
| assignar.com | `@assignar/api-schemas` | scoped pkg | `github:assignar/eslint-config-assignar/master/package.json` |
| auctelia.com | `@auctelia` | scope decl (.npmrc) | `github:auctelia/kosa/master/.npmrc` |
| biltrewards.com | `@addresscloud/eslint-config` | scoped pkg | `github:biltrewards/terraform-cloud-action/master/package.json` |
| blackbaud.com | `@blackbaud-internal/skyux-angular-builders` | scoped pkg | `github:blackbaud/skyux-spa-addin-hello-world/master/package.json` |
| clickup.com | `@time-loop/clickup-projen` | scoped pkg | `github:clickup/cdk-lambda-eni-usage-metric-publisher/main/package.json` |
| contentful.com | `eslint-plugin-custom-lingui` | bare pkg | `github:contentful/field-editors/master/package.json` |
| csats.com | `@slee204` | scope decl (.npmrc) | `github:csats/jnj-ds-ux-elements/master/.npmrc` |
| eyelock.com | `grunt-taskregistry` | bare pkg | `github:eyelock/aa-indiana/master/package.json` |
| financeit.io | `@adfinis-sygroup/semantic-release-config` | scoped pkg | `github:financeit/ember-validated-form/master/package.json` |
| fiverr.com | `@fiverr-private/obs` | scoped pkg | `github:fiverr/eslint-config-fiverr/master/package.json` |
| getmimo.com | `@getmimo` | scope decl (.npmrc) | `github:getmimo/sphinx/master/.npmrc` |
| givelegacy.com | `@vendure-hub` | scope decl (.npmrc) | `github:givelegacy/pinelab-vendure-plugins/main/.npmrc` |
| hootsuite.com | `hootsuite-bento` | bare pkg | `github:hootsuite/embedded-apps-template/main/package.json` |
| hyper.online | `eslint-config-zippin` | bare pkg | `github:hyper/react-zippin/main/package.json` |
| jamf.com | `@jamf` | scope decl (.npmrc) | `github:jamf/n8n/master/.npmrc` |
| internxt.com | `inxt-service-mailer` | bare pkg | `github:internxt/bridge/master/package.json` |
| kaltura.com | `@kaltura` | scope decl (.npmrc) | `github:kaltura/playkit-js-ui/master/.npmrc` |
| legalzoom.com | `@legalzoom` | scope decl (.npmrc) | `github:legalzoom/todo-mcp-server/main/.npmrc` |
| linode.com | `@redkubes` | scope decl (.npmrc) | `github:linode/apl-api/main/.npmrc` |
| lowes.com | `@lowes` | scope decl (.npmrc) | `github:lowes/product-viewer/main/.npmrc` |
| mode.com | `@viz/muze` | scoped pkg | `github:mode/pt-export/main/package.json` |
| normative.io | `HTML_CodeSniffer` | bare pkg | `github:normative/AccessSniff/master/package.json` |
| okta.com | `@repo/eslint-config` | scoped pkg | `github:okta/okta-client-javascript/master/package.json` |
| onemedical.com | `@onemedical` | scope decl (.npmrc) | `github:onemedical/cypress-circleci-reporter/master/.npmrc` |
| outdoorsy.co | `@outdoorsyco/crowdin-api` | scoped pkg | `github:outdoorsy/ember-cli-crowdin/master/package.json` |
| percent.com | `percent-auth-middleware` | bare pkg | `github:percent/twitter-example-app/master/package.json` |
| radixdlt.com | `uWebSockets.js` | bare pkg | `github:radixdlt/signaling-server/main/package.json` |
| redex.eco | `redex-scripts` | bare pkg | `github:redex/data/master/package.json` |
| relayplatform.com | `@relayplatform` | scope decl (.npmrc) | `github:relayplatform/rjsf-conditionals/main/.npmrc` |
| retool.com | `bundledDependencies` | bare pkg | `github:retool/azure-ghost/master/package.json` |
| seekingalpha.com | `@seekingalpha` | scope decl (.npmrc) | `github:seekingalpha/javascript/master/.npmrc` |
| shinetext.com | `@jonuy/referral-codes` | scoped pkg | `github:shinetext/aurora/main/package.json` |
| sleepycat.in | `@jsr` | scope decl (.npmrc) | `github:sleepycat/fp3/main/.npmrc` |
| spectrocloud.com | `@spectrocloud` | scope decl (.npmrc) | `github:spectrocloud/palette-sdk-typescript/main/.npmrc` |
| sunsave.energy | `@sunsave` | scope decl (.npmrc) | `github:sunsave/nestjs-sentry/main/.npmrc` |
| talentpair.com | `@talentpair/kyoto` | scoped pkg | `github:talentpair/talentpair-elm/master/package.json` |
| toggl.com | `@toggl/prettier` | scoped pkg | `github:toggl/track-extension/master/package.json` |
| tourlane.com | `@tourlane/fusion-you` | scoped pkg | `github:tourlane/fusion-you-test-app/main/package.json` |
| travelperk.com | `@jsr` | scope decl (.npmrc) | `github:travelperk/label-requires-reviews-action/main/.npmrc` |
| tryriot.com | `@tryriot/global-id` | scoped pkg | `github:tryriot/raycast-riot-global-id/master/package.json` |
| vetster.com | `@vetster` | scope decl (.npmrc) | `github:vetster/react-native-action-sheet/master/.npmrc` |
| zattoo.com | `@zattoo` | scope decl (.npmrc) | `github:zattoo/stylelint-config/master/.npmrc` |

## ℹ️ Low-risk notes (scope owned, specific pkg missing)

- **adtonos.com**: `@adtonos`
- **air-closet.com**: `@air-closet`
- **atroposhealth.com**: `@jupiterone/dev-tools`
- **bespoken.io**: `@bespoken-api/nlu`, `@bespoken-api/nlp`, `@bespoken-api/tts`
- **certifaction.com**: `@certifaction/vue3-webapp-config`, `@certifaction`
- **ceros.com**: `@contentful`
- **chargetrip.com**: `@chargetrip/frontend-utilities`, `@chargetrip`
- **cipherstash.com**: `@cipherstash`
- **classdojo.com**: `@classdojo`
- **cline.bot**: `@clinebot`
- **cord.tech**: `@fortawesome/fontawesome-pro`
- **coveo.com**: `@coveord/release`
- **debitoor.com**: `@debitoor/nodeerrors`, `@debitoor/moduleconfig`
- **descope.com**: `@descope`
- **devrev.ai**: `@devrev`
- **draftbit.com**: `@fortawesome/pro-thin-svg-icons`, `@fortawesome/sharp-solid-svg-icons`, `@fortawesome/pro-duotone-svg-icons`, `@fortawesome/pro-light-svg-icons`, `@fortawesome/pro-regular-svg-icons`, `@fortawesome/pro-solid-svg-icons`
- **fastly.com**: `@fastly`
- **fleetio.com**: `@activepieces`
- **fulcrumapp.com**: `@fulcrumapp/pg-query-deparser`, `@fulcrumapp/fulcrum-core`, `@fulcrumapp/pg-custom-types`, `@fulcrumapp`
- **gentrace.ai**: `@fortawesome/pro-regular-svg-icons`, `@fortawesome/pro-solid-svg-icons`
- **getjerry.com**: `@getjerry`
- **golee.it**: `@golee`
- **gopuff.com**: `@gopuff`
- **gorgias.io**: `@shopify`
- **gorgias.com**: `@shopify`
- **happeo.com**: `@universe/react-translations`
- **jebbit.com**: `@jebbit`
- **korukids.co.uk**: `@modelcontextprotocol`
- **lessonup.com**: `@instructure/js-utils`, `@instructure/ready`
- **lytics.com**: `@lytics`
- **metricool.com**: `@modelcontextprotocol`
- **mindee.com**: `@mindee/web-elements.assets`, `@mindee/web-elements.ui.card`, `@mindee/web-elements.ui.select-input`, `@mindee/web-elements.ui.spinner`, `@mindee/web-elements.ui.theme-wrapper`, `@mindee/web-elements.ui.typography`
- **mollie.com**: `@inpsyde/playwright-utils`
- **numan.com**: `@doist`
- **ordermentum.com**: `@ordermentum/eslint-config-ordermentum`, `@ordermentum`, `@steveojs`
- **packdigital.com**: `@shopify`
- **own3d.tv**: `@own3d/ext-types`
- **passbase.com**: `@passbase/react-native-passbase-v3`
- **penpot.app**: `@penpot/svgo`
- **recurly.com**: `@recurly/public-api-test-server`
- **redsift.com**: `@redsift/node-shared`
- **redsift.io**: `@redsift/node-shared`
- **rocketfuelblockchain.com**: `@trustwallet/types`
- **securityscorecard.io**: `@securityscorecard`
- **showbie.com**: `@showbie`
- **smartcar.com**: `@smartcar`, `@smartcar/eslint-plugin`, `@smartcar/prettier-config`
- **snaps.ltd**: `@google`
- **sproutsocial.com**: `@sproutsocial/marketing-build-tools`
- **styleseat.com**: `@circleci`
- **sumup.com**: `@sumup`
- **symbium.com**: `@zendesk`
- **ucloud.cn**: `@grafana`
- **usertesting.com**: `@lottiefiles`
- **voiceflow.com**: `@voiceflow/secrets-provider`, `@voiceflow/dbcli`, `@circleci/circleci-config-parser`
- **workato.com**: `@workato/svg-baker`, `@workato/svg-baker-runtime`, `@workato/svg-sprite-loader-runtime`
- **xometry.com**: `@xometry`
- **zapnito.com**: `@zestia/ember-template-lint-plugin`
- **zarela.io**: `@fortawesome/fontawesome-pro`, `@fortawesome`

