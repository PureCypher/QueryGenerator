import { initializeEventListeners, updateLogSources } from './ui/uiHandlers.js';
import { updateQueryOutput } from './query/queryGenerator.js';
import { queryLanguages } from './config/queryConfig.js';

document.addEventListener('DOMContentLoaded', () => {
    fetch('/queryLangs.json')
        .then(response => response.json())
        .then(data => {
            initializeQueryLanguageConfigs(data);
            initializeEventListeners();
            updateLogSources();
            updateQueryOutput();
        })
        .catch(error => {
            console.error('Error loading query language data:', error);
        });
});

function initializeQueryLanguageConfigs(data) {
    try {
        if (!data) {
            console.error('No query language data provided');
            return;
        }

        if (data.KQLtables) {
            data.KQLtables.forEach(table => {
                queryLanguages.kql.logSources[table.TableName.toLowerCase()] = table.Purpose;
            });
        }

        if (data.SplunkLogSources) {
            data.SplunkLogSources.forEach(source => {
                queryLanguages.spl.logSources[`index=${source.SourceType.toLowerCase()}`] = source.Purpose;
            });
        }

        if (data.ElasticLogSources) {
            data.ElasticLogSources.forEach(source => {
                queryLanguages.eql.logSources[source.SourceType.toLowerCase()] = source.Purpose;
            });
        }
    } catch (error) {
        console.error('Error initializing query language data:', error);
    }
}
