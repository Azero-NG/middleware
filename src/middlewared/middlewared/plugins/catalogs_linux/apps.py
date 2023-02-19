from middlewared.schema import Bool, Dict, List, Str
from middlewared.service import filterable, filterable_returns, job, Service
from middlewared.utils import filter_list


class AppService(Service):

    @filterable
    @filterable_returns(Dict(
        'available_apps',
        Bool('healthy', required=True),
        List('categories', required=True),
        Str('name', required=True),
        Str('title', required=True),
        Str('description', required=True),
        Str('app_readme', required=True),
        Str('location', required=True),
        Str('healthy_error', required=True, null=True),
        Str('latest_version', required=True),
        Str('latest_app_version', required=True),
        Str('icon_url', required=True),
        Str('train', required=True),
        Str('catalog', required=True),
    ))
    @job(lock='available_apps', lock_queue_size=1)
    def available(self, job, filters, options):
        results = []
        catalogs = self.middleware.call_sync('catalog.query')
        total_catalogs = len(catalogs)
        job.set_progress(5, 'Retrieving available apps from catalog(s)')

        def progress(index):
            return 10 + ((index + 1 / total_catalogs) * 80)

        for index, catalog in enumerate(catalogs):
            items_job = self.middleware.call_sync('catalog.items', catalog['label'])
            items_job.wait_sync()
            if items_job.error:
                job.set_progress(progress(index), f'Failed to retrieve apps from {catalog["label"]!r}')
                continue

            catalog_items = items_job.result
            for train, train_data in catalog_items.items():
                for app_data in train_data.values():
                    results.append({
                        'catalog': catalog['label'],
                        'train': train,
                        **app_data,
                    })

            job.set_progress(progress(index), f'Completed retrieving apps from {catalog["label"]!r}')

        return filter_list(results, filters, options)
