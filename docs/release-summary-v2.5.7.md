# AdversaryGraph v2.5.7 Release Summary

AdversaryGraph v2.5.7 expands external LLM provider support with MiniMax.

The platform now supports Claude, OpenAI, Gemini, MiniMax, and local/private
OpenAI-compatible LLM gateways for AI-assisted report analysis and optional IOC
AI-enrichment fallback.

## Operator Value

- MiniMax can be selected directly from the AI Analysis screen.
- MiniMax can be used from the embedded Navigator AI chat.
- MiniMax can be selected for optional IOC-to-TTP AI fallback during feed sync
  and enrichment workflows.
- Docker Compose forwards MiniMax configuration into the API and worker
  containers, so `.env` deployment behaves like the other cloud providers.
- Self-test reports whether `MINIMAX_API_KEY` is configured without exposing
  the secret.
## Configuration

```env
MINIMAX_API_KEY=your_key_here
MINIMAX_MODEL=MiniMax-M3
MINIMAX_BASE_URL=https://api.minimax.io/v1
```

## Verification

- Docker Compose config validation passed.
- Backend source compile check passed.
- Focused backend unit tests passed.
- Frontend production build passed.
- Docusaurus documentation build passed.
- 1200km internal link check passed.

## Release Links

- GitHub release: https://github.com/anpa1200/adversarygraph/releases/tag/v2.5.7
- Repository: https://github.com/anpa1200/adversarygraph
- Documentation: https://1200km.com/adversarygraph-docs/
- Project hub: https://1200km.com/adversarygraph/
- Published v2.5 article: https://medium.com/@1200km/adversarygraph-v2-5-new-name-new-release-full-ai-cti-platform-capability-map-93cd9224127e
- 1200km article mirror: https://1200km.com/articles/adversarygraph-v2-self-hosted-ai-cti-platform.html
- Full guide: `docs/full-guide-v2.md`
- Detailed notes: `docs/release-notes/v2.5.7.md`
